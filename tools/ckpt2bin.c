/*
 * ckpt2bin.c - Convert TensorFlow GPT-2 checkpoint to simple binary format
 *
 * This tool parses the TensorFlow SSTable index format and extracts tensors
 * from the checkpoint data file, writing them in a fixed order suitable for
 * inference.
 *
 * Usage: ckpt2bin <checkpoint_dir> <output.bin>
 *
 * No libc - uses only Linux syscalls.
 */

#include "mc.h"
#include "mc_mathf.h"

/* ============================================================================
 * Output format header
 * ============================================================================ */

#define GPT2_MAGIC 0x32545047  /* "GPT2" little-endian */

/* v2: f32 weights; matrices stored transposed as [out_dim,in_dim]
 * v3: like v2, but some matrices stored quantized with per-row scales
 */
#define GPT2_VERSION_F32 2
#define GPT2_VERSION_Q   3

#define GPT2_QTYPE_F32 0
#define GPT2_QTYPE_Q8  1
#define GPT2_QTYPE_Q4  2

static int parse_quantize_arg(const char *s)
{
	if (!s) return GPT2_QTYPE_F32;
	if (mc_streq(s, "q8")) return GPT2_QTYPE_Q8;
	if (mc_streq(s, "q4")) return GPT2_QTYPE_Q4;
	return -1;
}

static mc_u64 qmat_storage_bytes(int qtype, mc_u32 in_dim, mc_u32 out_dim)
{
	if (qtype == GPT2_QTYPE_Q8) {
		return (mc_u64)out_dim * 4u + (mc_u64)out_dim * (mc_u64)in_dim;
	}
	if (qtype == GPT2_QTYPE_Q4) {
		return (mc_u64)out_dim * 4u + (mc_u64)out_dim * (mc_u64)((in_dim + 1u) / 2u);
	}
	return (mc_u64)in_dim * (mc_u64)out_dim * 4u;
}

static mc_u32 pad16_bytes(mc_u64 off)
{
	return (mc_u32)((16u - (mc_u32)(off & 15u)) & 15u);
}

static void write_pad16(mc_i32 out_fd, mc_u64 *bytes_written, const char *ctx)
{
	mc_u32 pad = pad16_bytes(*bytes_written);
	if (!pad) return;
	mc_u8 zeros[16];
	mc_memset(zeros, 0, sizeof(zeros));
	if (mc_write_all(out_fd, zeros, pad) < 0) {
		mc_die_errno("ckpt2bin", ctx, -1);
	}
	*bytes_written += pad;
}

static mc_u64 qmat_pad16_bytes(int qtype, mc_u32 in_dim, mc_u32 out_dim)
{
	mc_u64 qb = qmat_storage_bytes(qtype, in_dim, out_dim);
	return (mc_u64)pad16_bytes(qb);
}

struct gpt2_header {
	mc_u32 magic;
	mc_u32 version;
	mc_u32 n_vocab;
	mc_u32 n_ctx;
	mc_u32 n_embd;
	mc_u32 n_head;
	mc_u32 n_layer;
	mc_u32 reserved[9];  /* Pad to 64 bytes */
};

/* ============================================================================
 * Tensor entry from checkpoint index
 * ============================================================================ */

#define MAX_TENSORS 2048
#define MAX_DIMS 4

struct tensor_entry {
	mc_u64 offset;
	mc_u64 size;
	mc_u32 dims[MAX_DIMS];
	mc_u32 ndims;
	char name[96];
};

static struct tensor_entry g_tensors[MAX_TENSORS];
static mc_u32 g_num_tensors = 0;

static int tensor_match_1d(const struct tensor_entry *t, mc_u32 d0, mc_u64 expected_size)
{
	if (!t) return 0;
	if (t->ndims != 1) return 0;
	if (t->dims[0] != d0) return 0;
	return t->size == expected_size;
}

static int tensor_match_2d(const struct tensor_entry *t, mc_u32 d0, mc_u32 d1, mc_u64 expected_size)
{
	if (!t) return 0;
	if (t->ndims != 2) return 0;
	if (t->dims[0] != d0) return 0;
	if (t->dims[1] != d1) return 0;
	return t->size == expected_size;
}

static int tensor_match_3d1(const struct tensor_entry *t, mc_u32 d1, mc_u32 d2, mc_u64 expected_size)
{
	if (!t) return 0;
	if (t->ndims != 3) return 0;
	if (t->dims[0] != 1) return 0;
	if (t->dims[1] != d1) return 0;
	if (t->dims[2] != d2) return 0;
	return t->size == expected_size;
}

static int tensor_match_mat_3d1_or_2d(const struct tensor_entry *t, mc_u32 in_dim, mc_u32 out_dim, mc_u64 expected_size)
{
	if (tensor_match_3d1(t, in_dim, out_dim, expected_size)) return 1;
	if (!t) return 0;
	if (t->ndims == 2 && t->dims[0] == in_dim && t->dims[1] == out_dim && t->size == expected_size) return 1;
	return 0;
}

/* ============================================================================
 * Protobuf varint decoding
 * ============================================================================ */

static mc_u64 read_varint(const mc_u8 *data, mc_usize len, mc_usize *pos) {
	mc_u64 result = 0;
	mc_u32 shift = 0;
	while (*pos < len) {
		mc_u8 b = data[*pos];
		(*pos)++;
		result |= (mc_u64)(b & 0x7F) << shift;
		if ((b & 0x80) == 0) break;
		shift += 7;
	}
	return result;
}

static mc_u32 read_fixed32_le(const mc_u8 *data) {
	return (mc_u32)data[0] | ((mc_u32)data[1] << 8) | ((mc_u32)data[2] << 16) | ((mc_u32)data[3] << 24);
}

/* ============================================================================
 * Parse shape from TensorShapeProto bytes
 * ============================================================================ */

static void parse_shape(const mc_u8 *data, mc_usize len, struct tensor_entry *entry) {
	entry->ndims = 0;
	mc_usize pos = 0;
	while (pos < len && entry->ndims < MAX_DIMS) {
		mc_u8 tag = data[pos];
		mc_u32 field = tag >> 3;
		mc_u32 wire = tag & 7;
		pos++;

		if (field == 2 && wire == 2) {
			/* dim submessage */
			mc_u64 dlen = read_varint(data, len, &pos);
			mc_usize dim_end = pos + (mc_usize)dlen;
			/* Parse dim.size (field 1, varint) */
			while (pos < dim_end && pos < len) {
				mc_u8 dtag = data[pos];
				mc_u32 dfield = dtag >> 3;
				mc_u32 dwire = dtag & 7;
				pos++;
				if (dfield == 1 && dwire == 0) {
					mc_u64 size = read_varint(data, len, &pos);
					entry->dims[entry->ndims++] = (mc_u32)size;
					break;
				} else if (dwire == 0) {
					(void)read_varint(data, len, &pos);
				} else if (dwire == 2) {
					mc_u64 skip = read_varint(data, len, &pos);
					pos += (mc_usize)skip;
				}
			}
			pos = dim_end;
		} else if (wire == 0) {
			(void)read_varint(data, len, &pos);
		} else if (wire == 2) {
			mc_u64 skip = read_varint(data, len, &pos);
			pos += (mc_usize)skip;
		}
	}
}

/* ============================================================================
 * Parse checkpoint index file
 * ============================================================================ */

static int parse_tensor_value(const mc_u8 *data, mc_usize len, struct tensor_entry *entry, int *out_is_float)
{
	if (!data || !entry || !out_is_float) return -1;
	*out_is_float = 0;
	entry->offset = 0;
	entry->size = 0;
	entry->ndims = 0;

	mc_usize pos = 0;
	while (pos < len) {
		mc_u8 tag = data[pos++];
		mc_u32 field = tag >> 3;
		mc_u32 wire = tag & 7;

		if (wire == 0) {
			mc_u64 v = read_varint(data, len, &pos);
			if (field == 1) {
				/* dtype: 1 = DT_FLOAT */
				if (v == 1) *out_is_float = 1;
			} else if (field == 4) {
				entry->offset = v;
			} else if (field == 5) {
				entry->size = v;
			}
		} else if (wire == 2) {
			mc_u64 l = read_varint(data, len, &pos);
			if (pos + (mc_usize)l > len) return -1;
			if (field == 2) {
				parse_shape(data + pos, (mc_usize)l, entry);
			}
			pos += (mc_usize)l;
		} else if (wire == 5) {
			/* fixed32 */
			if (pos + 4 > len) return -1;
			pos += 4;
		} else if (wire == 1) {
			/* fixed64 */
			if (pos + 8 > len) return -1;
			pos += 8;
		} else {
			return -1;
		}
	}

	return 0;
}

struct block_handle {
	mc_u64 offset;
	mc_u64 size;
};

static int parse_block_handle(const mc_u8 *data, mc_usize len, mc_usize *pos, mc_usize limit, struct block_handle *out)
{
	if (!data || !pos || !out) return -1;
	(void)len;
	if (*pos >= limit) return -1;
	/* varint64 offset, varint64 size */
	mc_usize p = *pos;
	mc_u64 off = read_varint(data, limit, &p);
	mc_u64 sz = read_varint(data, limit, &p);
	if (p > limit) return -1;
	out->offset = off;
	out->size = sz;
	*pos = p;
	return 0;
}

static int iterate_leveldb_block(const mc_u8 *block, mc_usize block_len,
	int (*cb)(const mc_u8 *key, mc_usize key_len, const mc_u8 *val, mc_usize val_len, void *ctx), void *ctx)
{
	if (!block || block_len < 4 || !cb) return -1;

	mc_u32 num_restarts = read_fixed32_le(block + (block_len - 4));
	mc_usize restart_off = block_len - 4u - (mc_usize)num_restarts * 4u;
	if (restart_off > block_len) return -1;

	char last_key[256];
	mc_usize last_key_len = 0;

	mc_usize pos = 0;
	while (pos < restart_off) {
		mc_u64 shared64 = read_varint(block, restart_off, &pos);
		mc_u64 non_shared64 = read_varint(block, restart_off, &pos);
		mc_u64 val_len64 = read_varint(block, restart_off, &pos);
		mc_usize shared = (mc_usize)shared64;
		mc_usize non_shared = (mc_usize)non_shared64;
		mc_usize val_len = (mc_usize)val_len64;

		if (shared > last_key_len) return -1;
		if (pos + non_shared + val_len > restart_off) return -1;
		if (shared + non_shared > sizeof(last_key)) {
			return -1;
		}

		/* reconstruct key */
		mc_usize new_len = shared + non_shared;
		for (mc_usize i = 0; i < non_shared; i++) {
			last_key[shared + i] = (char)block[pos + i];
		}
		last_key_len = new_len;

		const mc_u8 *val = block + pos + non_shared;
		if (cb((const mc_u8 *)last_key, last_key_len, val, val_len, ctx) != 0) return -1;
		pos += non_shared + val_len;
	}

	return 0;
}

struct parse_ctx {
	const mc_u8 *file;
	mc_usize file_len;
};

struct index_iter_ctx {
	struct parse_ctx *pctx;
};

static int parse_data_block_cb(const mc_u8 *key, mc_usize key_len, const mc_u8 *val, mc_usize val_len, void *vctx)
{
	struct parse_ctx *ctx = (struct parse_ctx *)vctx;
	(void)ctx;
	if (g_num_tensors >= MAX_TENSORS) {
		(void)mc_write_str(2, "ckpt2bin: too many tensors (increase MAX_TENSORS)\n");
		return -1;
	}
	if (!key || !val) return 0;

	struct tensor_entry *entry = &g_tensors[g_num_tensors];
	entry->name[0] = 0;
	if (key_len > 0) {
		mc_usize n = key_len;
		if (n >= sizeof(entry->name)) n = sizeof(entry->name) - 1;
		for (mc_usize i = 0; i < n; i++) entry->name[i] = (char)key[i];
		entry->name[n] = 0;
	}

	int is_float = 0;
	if (parse_tensor_value(val, val_len, entry, &is_float) != 0) return -1;
	if (!is_float) return 0;
	if (entry->size == 0) return 0;
	g_num_tensors++;
	return 0;
}

static int parse_index_block_cb(const mc_u8 *key, mc_usize key_len, const mc_u8 *val, mc_usize val_len, void *vctx)
{
	(void)key;
	(void)key_len;
	struct index_iter_ctx *ictx = (struct index_iter_ctx *)vctx;
	if (!ictx || !ictx->pctx) return -1;
	struct parse_ctx *pctx = ictx->pctx;

	mc_usize p = 0;
	struct block_handle h;
	h.offset = read_varint(val, val_len, &p);
	h.size = read_varint(val, val_len, &p);
	if (h.size == 0) return -1;
	if (h.offset + h.size > (mc_u64)pctx->file_len) return -1;
	const mc_u8 *blk = pctx->file + (mc_usize)h.offset;
	mc_usize blk_len = (mc_usize)h.size;
	if (iterate_leveldb_block(blk, blk_len, parse_data_block_cb, pctx) != 0) return -1;
	return 0;
}

static int parse_index(const mc_u8 *data, mc_usize len)
{
	/* LevelDB table format (sstable) with footer magic. */
	if (!data || len < 48) return -1;
	const mc_u64 magic = (mc_u64)0xdb4775248b80fb57ULL;
	mc_u64 file_magic = 0;
	for (int i = 0; i < 8; i++) file_magic |= (mc_u64)data[len - 8 + (mc_usize)i] << (8 * i);
	if (file_magic != magic) {
		(void)mc_write_str(2, "ckpt2bin: index is not a LevelDB table\n");
		return -1;
	}

	/* TensorFlow's table footer uses back-to-back varint BlockHandles in the first 40 bytes. */
	mc_usize footer = len - 48;
	mc_usize limit = footer + 40;
	mc_usize pos = footer;
	struct block_handle meta;
	struct block_handle index;
	if (parse_block_handle(data, len, &pos, limit, &meta) != 0) return -1;
	if (parse_block_handle(data, len, &pos, limit, &index) != 0) return -1;
	if (index.size == 0) {
		(void)mc_write_str(2, "ckpt2bin: index block handle missing\n");
		return -1;
	}
	if (index.offset + index.size > (mc_u64)len) return -1;

	const mc_u8 *index_block = data + (mc_usize)index.offset;
	mc_usize index_len = (mc_usize)index.size;

	/* The index block values are BlockHandles to data blocks. */
	struct parse_ctx ctx;
	ctx.file = data;
	ctx.file_len = len;
	struct index_iter_ctx ictx;
	ictx.pctx = &ctx;
	(void)meta;

	/* Iterate index block, parse each pointed-to data block. */
	if (iterate_leveldb_block(index_block, index_len, parse_index_block_cb, &ictx) != 0) return -1;
	return 0;
}

/* ============================================================================
 * Sort tensors by offset (simple insertion sort)
 * ============================================================================ */

#ifdef CKPT2BIN_SELFTEST

static void sort_tensors_by_offset(void) {
	for (mc_u32 i = 1; i < g_num_tensors; i++) {
		struct tensor_entry tmp = g_tensors[i];
		mc_u32 j = i;
		while (j > 0 && g_tensors[j - 1].offset > tmp.offset) {
			g_tensors[j] = g_tensors[j - 1];
			j--;
		}
		g_tensors[j] = tmp;
	}
}

/* ============================================================================
 * Tensor matching helpers
 * ============================================================================ */

static int find_tensor_wte(mc_u32 *used, struct tensor_entry **out, mc_u32 n_vocab, mc_u32 n_embd, mc_u64 expected_size)
{
	for (mc_u32 i = 0; i < g_num_tensors; i++) {
		if (used[i]) continue;
		struct tensor_entry *t = &g_tensors[i];
		if (tensor_match_2d(t, n_vocab, n_embd, expected_size) || tensor_match_3d1(t, n_vocab, n_embd, expected_size)) {
			used[i] = 1;
			*out = t;
			return 0;
		}
	}
	return -1;
}

static int find_tensor_wpe(mc_u32 *used, struct tensor_entry **out, mc_u32 n_ctx, mc_u32 n_embd, mc_u64 expected_size)
{
	for (mc_u32 i = 0; i < g_num_tensors; i++) {
		if (used[i]) continue;
		struct tensor_entry *t = &g_tensors[i];
		if (tensor_match_2d(t, n_ctx, n_embd, expected_size) || tensor_match_3d1(t, n_ctx, n_embd, expected_size)) {
			used[i] = 1;
			*out = t;
			return 0;
		}
	}
	return -1;
}

#endif

static struct tensor_entry *find_tensor_by_name(const char *name)
{
	if (!name) return MC_NULL;
	for (mc_u32 i = 0; i < g_num_tensors; i++) {
		if (mc_streq(g_tensors[i].name, name)) return &g_tensors[i];
	}
	return MC_NULL;
}

static void die_missing_tensor(const char *prog, const char *name)
{
	(void)mc_write_str(2, prog);
	(void)mc_write_str(2, ": missing tensor: ");
	(void)mc_write_str(2, name);
	(void)mc_write_str(2, "\n");
	mc_exit(1);
}

static int write_tensor_raw_checked(mc_i32 out_fd, const mc_u8 *data_base, mc_usize data_size, const struct tensor_entry *t)
{
	if (!t) return -1;
	if (t->offset > (mc_u64)data_size) return -1;
	if (t->size > (mc_u64)data_size) return -1;
	if (t->offset + t->size > (mc_u64)data_size) return -1;
	if ((t->offset & 3u) != 0) return -1;

	mc_i64 r = mc_write_all(out_fd, data_base + t->offset, (mc_usize)t->size);
	return (r < 0) ? -1 : 0;
}

static int write_tensor_transposed_mat_checked(mc_i32 out_fd, const mc_u8 *data_base, mc_usize data_size, const struct tensor_entry *t,
	mc_u32 in_dim, mc_u32 out_dim)
{
	if (!t) return -1;
	if (!tensor_match_mat_3d1_or_2d(t, in_dim, out_dim, (mc_u64)in_dim * (mc_u64)out_dim * 4u)) return -1;
	if (t->offset > (mc_u64)data_size) return -1;
	if (t->size > (mc_u64)data_size) return -1;
	if (t->offset + t->size > (mc_u64)data_size) return -1;
	if ((t->offset & 3u) != 0) return -1;

	const float *src = (const float *)(data_base + t->offset);
	mc_i64 r = mc_write_transposed_f32(out_fd, src, in_dim, out_dim);
	return (r < 0) ? -1 : 0;
}

static int write_q8_transposed_with_scales(mc_i32 out_fd, const float *src_in_out, mc_u32 in_dim, mc_u32 out_dim)
{
	/* src is [in_dim, out_dim] row-major; write scales[out_dim] then q8 for transposed [out_dim, in_dim]. */
	static mc_u8 rowq[4096];
	if (in_dim > (mc_u32)sizeof(rowq)) return -1;

	for (mc_u32 o = 0; o < out_dim; o++) {
		float maxabs = 0.0f;
		for (mc_u32 i = 0; i < in_dim; i++) {
			float w = src_in_out[i * out_dim + o];
			float a = (w < 0.0f) ? -w : w;
			if (a > maxabs) maxabs = a;
		}
		float s = maxabs / 127.0f;
		if (s == 0.0f) s = 1.0f;
		if (mc_write_all(out_fd, &s, 4) < 0) return -1;

		float inv = 1.0f / s;
		for (mc_u32 i = 0; i < in_dim; i++) {
			float w = src_in_out[i * out_dim + o] * inv;
			int qi = (w >= 0.0f) ? (int)(w + 0.5f) : (int)(w - 0.5f);
			if (qi > 127) qi = 127;
			if (qi < -127) qi = -127;
			rowq[i] = (mc_u8)(mc_i8)qi;
		}
		if (mc_write_all(out_fd, rowq, (mc_usize)in_dim) < 0) return -1;
	}

	return 0;
}

static int write_q8_rows_with_scales(mc_i32 out_fd, const float *src_out_in, mc_u32 out_dim, mc_u32 in_dim)
{
	/* src is [out_dim, in_dim] row-major; write interleaved [scale][row q] per row. */
	static mc_u8 rowq[4096];
	if (in_dim > (mc_u32)sizeof(rowq)) return -1;

	for (mc_u32 o = 0; o < out_dim; o++) {
		const float *rowf = src_out_in + (mc_usize)o * in_dim;
		float maxabs = 0.0f;
		for (mc_u32 i = 0; i < in_dim; i++) {
			float w = rowf[i];
			float a = (w < 0.0f) ? -w : w;
			if (a > maxabs) maxabs = a;
		}
		float s = maxabs / 127.0f;
		if (s == 0.0f) s = 1.0f;
		if (mc_write_all(out_fd, &s, 4) < 0) return -1;

		float inv = 1.0f / s;
		for (mc_u32 i = 0; i < in_dim; i++) {
			float w = rowf[i] * inv;
			int qi = (w >= 0.0f) ? (int)(w + 0.5f) : (int)(w - 0.5f);
			if (qi > 127) qi = 127;
			if (qi < -127) qi = -127;
			rowq[i] = (mc_u8)(mc_i8)qi;
		}
		if (mc_write_all(out_fd, rowq, (mc_usize)in_dim) < 0) return -1;
	}

	return 0;
}

static int write_q4_transposed_with_scales(mc_i32 out_fd, const float *src_in_out, mc_u32 in_dim, mc_u32 out_dim)
{
	/* q4 stored as signed 4-bit two's complement in nibbles ([-8..7]). */
	static mc_u8 rowq[(4096 + 1) / 2];
	if (((in_dim + 1u) / 2u) > (mc_u32)sizeof(rowq)) return -1;

	for (mc_u32 o = 0; o < out_dim; o++) {
		float maxabs = 0.0f;
		for (mc_u32 i = 0; i < in_dim; i++) {
			float w = src_in_out[i * out_dim + o];
			float a = (w < 0.0f) ? -w : w;
			if (a > maxabs) maxabs = a;
		}
		float s = maxabs / 7.0f;
		if (s == 0.0f) s = 1.0f;
		if (mc_write_all(out_fd, &s, 4) < 0) return -1;

		float inv = 1.0f / s;
		mc_u32 bi = 0;
		for (mc_u32 i = 0; i < in_dim; i += 2) {
			float w0 = src_in_out[(i + 0) * out_dim + o] * inv;
			int q0 = (w0 >= 0.0f) ? (int)(w0 + 0.5f) : (int)(w0 - 0.5f);
			if (q0 > 7) q0 = 7;
			if (q0 < -8) q0 = -8;
			mc_u8 n0 = (mc_u8)(q0 & 0xFu);

			mc_u8 n1 = 0;
			if (i + 1 < in_dim) {
				float w1 = src_in_out[(i + 1) * out_dim + o] * inv;
				int q1 = (w1 >= 0.0f) ? (int)(w1 + 0.5f) : (int)(w1 - 0.5f);
				if (q1 > 7) q1 = 7;
				if (q1 < -8) q1 = -8;
				n1 = (mc_u8)(q1 & 0xFu);
			}
			rowq[bi++] = (mc_u8)(n0 | (mc_u8)(n1 << 4));
		}
		if (mc_write_all(out_fd, rowq, (mc_usize)((in_dim + 1u) / 2u)) < 0) return -1;
	}

	return 0;
}

static int write_q4_rows_with_scales(mc_i32 out_fd, const float *src_out_in, mc_u32 out_dim, mc_u32 in_dim)
{
	static mc_u8 rowq[(4096 + 1) / 2];
	if (((in_dim + 1u) / 2u) > (mc_u32)sizeof(rowq)) return -1;

	for (mc_u32 o = 0; o < out_dim; o++) {
		const float *rowf = src_out_in + (mc_usize)o * in_dim;
		float maxabs = 0.0f;
		for (mc_u32 i = 0; i < in_dim; i++) {
			float w = rowf[i];
			float a = (w < 0.0f) ? -w : w;
			if (a > maxabs) maxabs = a;
		}
		float s = maxabs / 7.0f;
		if (s == 0.0f) s = 1.0f;
		if (mc_write_all(out_fd, &s, 4) < 0) return -1;

		float inv = 1.0f / s;
		mc_u32 bi = 0;
		for (mc_u32 i = 0; i < in_dim; i += 2) {
			float w0 = rowf[i + 0] * inv;
			int q0 = (w0 >= 0.0f) ? (int)(w0 + 0.5f) : (int)(w0 - 0.5f);
			if (q0 > 7) q0 = 7;
			if (q0 < -8) q0 = -8;
			mc_u8 n0 = (mc_u8)(q0 & 0xFu);

			mc_u8 n1 = 0;
			if (i + 1 < in_dim) {
				float w1 = rowf[i + 1] * inv;
				int q1 = (w1 >= 0.0f) ? (int)(w1 + 0.5f) : (int)(w1 - 0.5f);
				if (q1 > 7) q1 = 7;
				if (q1 < -8) q1 = -8;
				n1 = (mc_u8)(q1 & 0xFu);
			}
			rowq[bi++] = (mc_u8)(n0 | (mc_u8)(n1 << 4));
		}
		if (mc_write_all(out_fd, rowq, (mc_usize)((in_dim + 1u) / 2u)) < 0) return -1;
	}

	return 0;
}

static int write_tensor_transposed_quant_checked(mc_i32 out_fd, const mc_u8 *data_base, mc_usize data_size, const struct tensor_entry *t,
	mc_u32 in_dim, mc_u32 out_dim, int qtype)
{
	if (!t) return -1;
	if (!tensor_match_mat_3d1_or_2d(t, in_dim, out_dim, (mc_u64)in_dim * (mc_u64)out_dim * 4u)) return -1;
	if (t->offset > (mc_u64)data_size) return -1;
	if (t->size > (mc_u64)data_size) return -1;
	if (t->offset + t->size > (mc_u64)data_size) return -1;
	if ((t->offset & 3u) != 0) return -1;

	const float *src = (const float *)(data_base + t->offset);
	if (qtype == GPT2_QTYPE_Q8) return write_q8_transposed_with_scales(out_fd, src, in_dim, out_dim);
	if (qtype == GPT2_QTYPE_Q4) return write_q4_transposed_with_scales(out_fd, src, in_dim, out_dim);
	return -1;
}

#ifdef CKPT2BIN_SELFTEST

static int is_expected_layer_block(struct tensor_entry **layer_t, mc_u32 n_embd,
	mc_u64 ln_size, mc_u64 c_attn_b_size, mc_u64 c_attn_w_size, mc_u64 c_proj_w_size,
	mc_u64 c_fc_b_size, mc_u64 c_fc_w_size, mc_u64 c_proj2_w_size)
{
	if (!tensor_match_1d(layer_t[0], 3 * n_embd, c_attn_b_size)) return 0;
	if (!tensor_match_mat_3d1_or_2d(layer_t[1], n_embd, 3 * n_embd, c_attn_w_size)) return 0;
	if (!tensor_match_1d(layer_t[2], n_embd, ln_size)) return 0;
	if (!tensor_match_mat_3d1_or_2d(layer_t[3], n_embd, n_embd, c_proj_w_size)) return 0;
	if (!tensor_match_1d(layer_t[4], n_embd, ln_size)) return 0;
	if (!tensor_match_1d(layer_t[5], n_embd, ln_size)) return 0;
	if (!tensor_match_1d(layer_t[6], n_embd, ln_size)) return 0;
	if (!tensor_match_1d(layer_t[7], n_embd, ln_size)) return 0;
	if (!tensor_match_1d(layer_t[8], 4 * n_embd, c_fc_b_size)) return 0;
	if (!tensor_match_mat_3d1_or_2d(layer_t[9], n_embd, 4 * n_embd, c_fc_w_size)) return 0;
	if (!tensor_match_1d(layer_t[10], n_embd, ln_size)) return 0;
	if (!tensor_match_mat_3d1_or_2d(layer_t[11], 4 * n_embd, n_embd, c_proj2_w_size)) return 0;
	return 1;
}

static int find_next_layer_block(mc_u32 *used, mc_u32 *io_scan, struct tensor_entry **layer_t, mc_u32 n_embd,
	mc_u64 ln_size, mc_u64 c_attn_b_size, mc_u64 c_attn_w_size, mc_u64 c_proj_w_size,
	mc_u64 c_fc_b_size, mc_u64 c_fc_w_size, mc_u64 c_proj2_w_size)
{
	if (!used || !io_scan || !layer_t) return -1;

	for (mc_u32 start = *io_scan; start < g_num_tensors; start++) {
		mc_u32 idx[12];
		mc_u32 j = start;
		mc_u32 n = 0;
		while (j < g_num_tensors && n < 12) {
			if (!used[j]) {
				layer_t[n] = &g_tensors[j];
				idx[n] = j;
				n++;
			}
			j++;
		}
		if (n < 12) return -1;
		if (!is_expected_layer_block(layer_t, n_embd, ln_size, c_attn_b_size, c_attn_w_size, c_proj_w_size, c_fc_b_size, c_fc_w_size, c_proj2_w_size)) {
			continue;
		}

		for (mc_u32 k = 0; k < 12; k++) used[idx[k]] = 1;
		*io_scan = j;
		return 0;
	}

	return -1;
}

#endif

/* ============================================================================
 * mmap helpers
 * ============================================================================ */

#define PROT_READ 1
#define MAP_PRIVATE 2

static void *map_file(const char *path, mc_usize *out_size) {
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY, 0);
	if (fd < 0) return MC_NULL;

	struct mc_stat st;
	if (mc_sys_fstat((mc_i32)fd, &st) < 0) {
		mc_sys_close((mc_i32)fd);
		return MC_NULL;
	}

	mc_i64 addr = mc_sys_mmap(MC_NULL, (mc_usize)st.st_size, PROT_READ, MAP_PRIVATE, (mc_i32)fd, 0);
	mc_sys_close((mc_i32)fd);

	if (addr < 0) return MC_NULL;
	*out_size = (mc_usize)st.st_size;
	return (void *)addr;
}

struct gpt2_hparams {
	mc_u32 n_vocab;
	mc_u32 n_ctx;
	mc_u32 n_embd;
	mc_u32 n_head;
	mc_u32 n_layer;
};

static int json_find_u32(const mc_u8 *buf, mc_usize len, const char *key, mc_u32 *out)
{
	if (!buf || !key || !out) return -1;
	mc_u32 key_len = (mc_u32)mc_strlen(key);
	if (key_len == 0) return -1;

	for (mc_usize i = 0; i + (mc_usize)key_len + 2u < len; i++) {
		if (buf[i] != '"') continue;
		/* match "key" */
		mc_usize j = i + 1;
		mc_u32 k = 0;
		while (k < key_len && (j + (mc_usize)k) < len && buf[j + k] == (mc_u8)key[k]) {
			k++;
		}
		if (k != key_len) continue;
		if (j + (mc_usize)key_len >= len || buf[j + key_len] != '"') continue;
		j = j + (mc_usize)key_len + 1;
		while (j < len && buf[j] != ':') j++;
		if (j >= len) return -1;
		j++;
		while (j < len) {
			mc_u8 c = buf[j];
			if (c == ' ' || c == '\n' || c == '\r' || c == '\t') { j++; continue; }
			break;
		}
		if (j >= len) return -1;
		mc_u64 v = 0;
		mc_usize start = j;
		while (j < len && buf[j] >= '0' && buf[j] <= '9') {
			v = v * 10u + (mc_u64)(buf[j] - '0');
			if (v > 0xFFFFFFFFu) return -1;
			j++;
		}
		if (j == start) return -1;
		*out = (mc_u32)v;
		return 0;
	}
	return -1;
}

static int read_hparams_json(struct gpt2_hparams *hp, const char *ckpt_dir)
{
	if (!hp || !ckpt_dir) return -1;
	mc_memset(hp, 0, sizeof(*hp));

	char path[512];
	mc_join_path_or_die("ckpt2bin", ckpt_dir, "hparams.json", path, sizeof(path));

	mc_usize sz = 0;
	const mc_u8 *buf = (const mc_u8 *)map_file(path, &sz);
	if (!buf || sz == 0) return -1;

	if (json_find_u32(buf, sz, "n_vocab", &hp->n_vocab) < 0) return -1;
	if (json_find_u32(buf, sz, "n_ctx", &hp->n_ctx) < 0) return -1;
	if (json_find_u32(buf, sz, "n_embd", &hp->n_embd) < 0) return -1;
	if (json_find_u32(buf, sz, "n_head", &hp->n_head) < 0) return -1;
	if (json_find_u32(buf, sz, "n_layer", &hp->n_layer) < 0) return -1;

	return 0;
}

/* ============================================================================
 * Main
 * ============================================================================ */

#ifdef CKPT2BIN_SELFTEST

static void ckpt2bin_die(const char *msg)
{
	(void)mc_write_str(2, msg);
	(void)mc_write_str(2, "\n");
	mc_exit(1);
}

int main(void)
{
	(void)mc_write_str(1, "=== ckpt2bin selftest ===\n");

	mc_u32 n_vocab = 50257;
	mc_u32 n_ctx = 1024;
	mc_u32 n_embd = 768;

	mc_u64 wte_size = (mc_u64)n_vocab * n_embd * 4;
	mc_u64 wpe_size = (mc_u64)n_ctx * n_embd * 4;
	mc_u64 ln_size = (mc_u64)n_embd * 4;
	mc_u64 c_attn_w_size = (mc_u64)n_embd * n_embd * 3 * 4;
	mc_u64 c_attn_b_size = (mc_u64)n_embd * 3 * 4;
	mc_u64 c_proj_w_size = (mc_u64)n_embd * n_embd * 4;
	mc_u64 c_fc_w_size = (mc_u64)n_embd * n_embd * 4 * 4;
	mc_u64 c_fc_b_size = (mc_u64)n_embd * 4 * 4;
	mc_u64 c_proj2_w_size = (mc_u64)n_embd * 4 * n_embd * 4;

	/* Build synthetic tensor table: wte, wpe, then one layer block. */
	g_num_tensors = 14;
	mc_memset(g_tensors, 0, sizeof(g_tensors));

	/* wte */
	g_tensors[0].offset = 0;
	g_tensors[0].size = wte_size;
	g_tensors[0].ndims = 2;
	g_tensors[0].dims[0] = n_vocab;
	g_tensors[0].dims[1] = n_embd;

	/* wpe */
	g_tensors[1].offset = g_tensors[0].offset + g_tensors[0].size;
	g_tensors[1].size = wpe_size;
	g_tensors[1].ndims = 2;
	g_tensors[1].dims[0] = n_ctx;
	g_tensors[1].dims[1] = n_embd;

	mc_u64 off = g_tensors[1].offset + g_tensors[1].size;

	/* layer tensors in checkpoint order */
	/* 0: c_attn/b [2304] */
	g_tensors[2].offset = off; g_tensors[2].size = c_attn_b_size; g_tensors[2].ndims = 1; g_tensors[2].dims[0] = 3 * n_embd; off += g_tensors[2].size;
	/* 1: c_attn/w [1,768,2304] */
	g_tensors[3].offset = off; g_tensors[3].size = c_attn_w_size; g_tensors[3].ndims = 3; g_tensors[3].dims[0] = 1; g_tensors[3].dims[1] = n_embd; g_tensors[3].dims[2] = 3 * n_embd; off += g_tensors[3].size;
	/* 2: c_proj/b [768] */
	g_tensors[4].offset = off; g_tensors[4].size = ln_size; g_tensors[4].ndims = 1; g_tensors[4].dims[0] = n_embd; off += g_tensors[4].size;
	/* 3: c_proj/w [1,768,768] */
	g_tensors[5].offset = off; g_tensors[5].size = c_proj_w_size; g_tensors[5].ndims = 3; g_tensors[5].dims[0] = 1; g_tensors[5].dims[1] = n_embd; g_tensors[5].dims[2] = n_embd; off += g_tensors[5].size;
	/* 4: ln_1/b [768] */
	g_tensors[6].offset = off; g_tensors[6].size = ln_size; g_tensors[6].ndims = 1; g_tensors[6].dims[0] = n_embd; off += g_tensors[6].size;
	/* 5: ln_1/g [768] */
	g_tensors[7].offset = off; g_tensors[7].size = ln_size; g_tensors[7].ndims = 1; g_tensors[7].dims[0] = n_embd; off += g_tensors[7].size;
	/* 6: ln_2/b [768] */
	g_tensors[8].offset = off; g_tensors[8].size = ln_size; g_tensors[8].ndims = 1; g_tensors[8].dims[0] = n_embd; off += g_tensors[8].size;
	/* 7: ln_2/g [768] */
	g_tensors[9].offset = off; g_tensors[9].size = ln_size; g_tensors[9].ndims = 1; g_tensors[9].dims[0] = n_embd; off += g_tensors[9].size;
	/* 8: c_fc/b [3072] */
	g_tensors[10].offset = off; g_tensors[10].size = c_fc_b_size; g_tensors[10].ndims = 1; g_tensors[10].dims[0] = 4 * n_embd; off += g_tensors[10].size;
	/* 9: c_fc/w [1,768,3072] */
	g_tensors[11].offset = off; g_tensors[11].size = c_fc_w_size; g_tensors[11].ndims = 3; g_tensors[11].dims[0] = 1; g_tensors[11].dims[1] = n_embd; g_tensors[11].dims[2] = 4 * n_embd; off += g_tensors[11].size;
	/* 10: c_proj2/b [768] */
	g_tensors[12].offset = off; g_tensors[12].size = ln_size; g_tensors[12].ndims = 1; g_tensors[12].dims[0] = n_embd; off += g_tensors[12].size;
	/* 11: c_proj2/w [1,3072,768] */
	g_tensors[13].offset = off; g_tensors[13].size = c_proj2_w_size; g_tensors[13].ndims = 3; g_tensors[13].dims[0] = 1; g_tensors[13].dims[1] = 4 * n_embd; g_tensors[13].dims[2] = n_embd;

	mc_u32 used[MAX_TENSORS];
	mc_memset(used, 0, sizeof(used));
	struct tensor_entry *wte;
	struct tensor_entry *wpe;
	if (find_tensor_wte(used, &wte, n_vocab, n_embd, wte_size) < 0) ckpt2bin_die("selftest: wte find failed");
	if (find_tensor_wpe(used, &wpe, n_ctx, n_embd, wpe_size) < 0) ckpt2bin_die("selftest: wpe find failed");

	struct tensor_entry *layer_t[12];
	mc_u32 scan = 0;
	if (find_next_layer_block(used, &scan, layer_t, n_embd,
		ln_size, c_attn_b_size, c_attn_w_size, c_proj_w_size,
		c_fc_b_size, c_fc_w_size, c_proj2_w_size) < 0) {
		ckpt2bin_die("selftest: layer block match failed");
	}

	(void)mc_write_str(1, "OK\n");
	mc_exit(0);
	return 0;
}

#else

int main(int argc, char **argv) {
	int qtype = GPT2_QTYPE_F32;
	int argi = 1;
	if (argc >= 3 && mc_streq(argv[1], "--quantize")) {
		if (argc < 5) {
			mc_die_usage(argv[0], "[--quantize q8|q4] <checkpoint_dir> <output.bin>");
		}
		qtype = parse_quantize_arg(argv[2]);
		if (qtype < 0) {
			mc_die_usage(argv[0], "[--quantize q8|q4] <checkpoint_dir> <output.bin>");
		}
		argi = 3;
	}
	if (argc - argi != 2) {
		mc_die_usage(argv[0], "[--quantize q8|q4] <checkpoint_dir> <output.bin>");
	}

	const char *ckpt_dir = argv[argi + 0];
	const char *out_path = argv[argi + 1];

	/* Build paths */
	char index_path[512];
	char data_path[512];

	mc_join_path_or_die(argv[0], ckpt_dir, "model.ckpt.index", index_path, sizeof(index_path));
	mc_join_path_or_die(argv[0], ckpt_dir, "model.ckpt.data-00000-of-00001", data_path, sizeof(data_path));

	/* Map index file */
	mc_usize index_size;
	const mc_u8 *index_data = (const mc_u8 *)map_file(index_path, &index_size);
	if (!index_data) {
		mc_die_errno(argv[0], "failed to map index file", -MC_ENOENT);
	}

	(void)mc_write_str(1, "Parsing checkpoint index...\n");

	/* Parse index */
	if (parse_index(index_data, index_size) < 0) {
		mc_exit(1);
	}

	(void)mc_write_str(1, "Found ");
	mc_write_u64_dec(1, g_num_tensors);
	(void)mc_write_str(1, " tensors\n");

	/* Index keys are full tensor names; we will map by name, not by offset order. */

	/* Read model dimensions from hparams.json */
	struct gpt2_hparams hp;
	if (read_hparams_json(&hp, ckpt_dir) < 0) {
		mc_die_errno(argv[0], "failed to read hparams.json", -MC_ENOENT);
	}

	/* Map data file */
	mc_usize data_size;
	const mc_u8 *data_base = (const mc_u8 *)map_file(data_path, &data_size);
	if (!data_base) {
		char data_zip_path[512];
		mc_join_path_or_die(argv[0], ckpt_dir, "model.ckpt.data-00000-of-00001.zip", data_zip_path, sizeof(data_zip_path));
		mc_i64 zfd = mc_sys_openat(MC_AT_FDCWD, data_zip_path, MC_O_RDONLY, 0);
		if (zfd >= 0) {
			mc_sys_close((mc_i32)zfd);
			(void)mc_write_str(2, "Error: checkpoint data file is zipped; please unzip it first:\n");
			(void)mc_write_str(2, "  unzip -n ");
			(void)mc_write_str(2, data_zip_path);
			(void)mc_write_str(2, " -d ");
			(void)mc_write_str(2, ckpt_dir);
			(void)mc_write_str(2, "\n");
			mc_exit(1);
		}
		mc_die_errno(argv[0], "failed to map data file", -MC_ENOENT);
	}

	(void)mc_write_str(1, "Data file size: ");
	mc_write_u64_dec(1, data_size);
	(void)mc_write_str(1, " bytes\n");

	/* Model dimensions from hparams.json */
	mc_u32 n_vocab = hp.n_vocab;
	mc_u32 n_ctx = hp.n_ctx;
	mc_u32 n_embd = hp.n_embd;
	mc_u32 n_head = hp.n_head;
	mc_u32 n_layer = hp.n_layer;
	if (n_vocab == 0 || n_ctx == 0 || n_embd == 0 || n_head == 0 || n_layer == 0) {
		mc_die_errno(argv[0], "invalid hparams.json", -1);
	}
	if ((n_embd % n_head) != 0) {
		mc_die_errno(argv[0], "hparams: n_embd must be divisible by n_head", -1);
	}

	/* Create output file */
	mc_i64 out_fd = mc_sys_openat(MC_AT_FDCWD, out_path,
		MC_O_WRONLY | MC_O_CREAT | MC_O_TRUNC, 0644);
	if (out_fd < 0) {
		mc_die_errno(argv[0], "failed to create output file", out_fd);
	}

	/* Write header */
	struct gpt2_header hdr;
	mc_memset(&hdr, 0, sizeof(hdr));
	hdr.magic = GPT2_MAGIC;
	hdr.version = (qtype == GPT2_QTYPE_F32) ? GPT2_VERSION_F32 : GPT2_VERSION_Q;
	hdr.n_vocab = n_vocab;
	hdr.n_ctx = n_ctx;
	hdr.n_embd = n_embd;
	hdr.n_head = n_head;
	hdr.n_layer = n_layer;
	hdr.reserved[0] = (mc_u32)qtype;
	/* reserved[1] bit0: whether wte is quantized */
	int wte_quant = (qtype == GPT2_QTYPE_Q8);
	hdr.reserved[1] = (mc_u32)(wte_quant ? 1u : 0u);

	if (mc_write_all((mc_i32)out_fd, &hdr, sizeof(hdr)) < 0) {
		mc_die_errno(argv[0], "failed to write header", -1);
	}

	(void)mc_write_str(1, "Writing tensors in inference order...\n");

	struct tensor_entry *t;
	mc_u64 bytes_written = sizeof(hdr);

	/* Expected sizes */
	mc_u64 wte_size = (mc_u64)n_vocab * n_embd * 4;
	mc_u64 wpe_size = (mc_u64)n_ctx * n_embd * 4;
	mc_u64 ln_size = (mc_u64)n_embd * 4;
	mc_u64 c_attn_b_size = (mc_u64)n_embd * 3 * 4;
	mc_u64 c_fc_b_size = (mc_u64)n_embd * 4 * 4;

	mc_u64 expected_layer_bytes = 0;
	expected_layer_bytes += 2 * ln_size; /* ln1_g, ln1_b */
	expected_layer_bytes += qmat_storage_bytes(qtype, n_embd, 3 * n_embd);
	if (qtype != GPT2_QTYPE_F32) expected_layer_bytes += qmat_pad16_bytes(qtype, n_embd, 3 * n_embd);
	expected_layer_bytes += c_attn_b_size;
	expected_layer_bytes += qmat_storage_bytes(qtype, n_embd, n_embd);
	if (qtype != GPT2_QTYPE_F32) expected_layer_bytes += qmat_pad16_bytes(qtype, n_embd, n_embd);
	expected_layer_bytes += ln_size; /* c_proj/b */
	expected_layer_bytes += 2 * ln_size; /* ln2_g, ln2_b */
	expected_layer_bytes += qmat_storage_bytes(qtype, n_embd, 4 * n_embd);
	if (qtype != GPT2_QTYPE_F32) expected_layer_bytes += qmat_pad16_bytes(qtype, n_embd, 4 * n_embd);
	expected_layer_bytes += c_fc_b_size;
	expected_layer_bytes += qmat_storage_bytes(qtype, 4 * n_embd, n_embd);
	if (qtype != GPT2_QTYPE_F32) expected_layer_bytes += qmat_pad16_bytes(qtype, 4 * n_embd, n_embd);
	expected_layer_bytes += ln_size; /* c_proj2/b */

	mc_u64 expected_total_bytes = (mc_u64)sizeof(hdr);
	if (wte_quant) {
		expected_total_bytes += qmat_storage_bytes(qtype, n_embd, n_vocab);
		if (qtype != GPT2_QTYPE_F32) expected_total_bytes += qmat_pad16_bytes(qtype, n_embd, n_vocab);
	}
	else expected_total_bytes += wte_size;
	expected_total_bytes += wpe_size;
	expected_total_bytes += (mc_u64)n_layer * expected_layer_bytes;
	expected_total_bytes += 2 * ln_size; /* ln_f_g + ln_f_b */

	/* 1. wte (token embeddings) */
	t = find_tensor_by_name("model/wte");
	if (!t) die_missing_tensor(argv[0], "model/wte");
	if (!(tensor_match_2d(t, n_vocab, n_embd, wte_size) || tensor_match_3d1(t, n_vocab, n_embd, wte_size))) {
		mc_die_errno(argv[0], "wte shape mismatch", -1);
	}
	(void)mc_write_str(1, "  wte: ");
	mc_write_u64_dec(1, t->size);
	(void)mc_write_str(1, " bytes\n");
	if (qtype == GPT2_QTYPE_F32 || !wte_quant) {
		if (write_tensor_raw_checked((mc_i32)out_fd, data_base, data_size, t) < 0) {
			mc_die_errno(argv[0], "write wte", -1);
		}
		bytes_written += t->size;
	} else {
		/* Quantized wte: source is already [out=n_vocab, in=n_embd] row-major. */
		if (t->offset > (mc_u64)data_size || t->offset + t->size > (mc_u64)data_size || ((t->offset & 3u) != 0)) {
			mc_die_errno(argv[0], "wte offset/size", -1);
		}
		const float *src = (const float *)(data_base + t->offset);
		int wr;
		if (qtype == GPT2_QTYPE_Q8) wr = write_q8_rows_with_scales((mc_i32)out_fd, src, n_vocab, n_embd);
		else wr = write_q4_rows_with_scales((mc_i32)out_fd, src, n_vocab, n_embd);
		if (wr < 0) {
			mc_die_errno(argv[0], "write wte quant", -1);
		}
		bytes_written += qmat_storage_bytes(qtype, n_embd, n_vocab);
		write_pad16((mc_i32)out_fd, &bytes_written, "write wte pad16");
	}

	/* 2. wpe (position embeddings) */
	t = find_tensor_by_name("model/wpe");
	if (!t) die_missing_tensor(argv[0], "model/wpe");
	if (!(tensor_match_2d(t, n_ctx, n_embd, wpe_size) || tensor_match_3d1(t, n_ctx, n_embd, wpe_size))) {
		mc_die_errno(argv[0], "wpe shape mismatch", -1);
	}
	(void)mc_write_str(1, "  wpe: ");
	mc_write_u64_dec(1, t->size);
	(void)mc_write_str(1, " bytes\n");
	if (write_tensor_raw_checked((mc_i32)out_fd, data_base, data_size, t) < 0) {
		mc_die_errno(argv[0], "write wpe", -1);
	}
	bytes_written += t->size;

	/* 3. For each layer, write in order */
	for (mc_u32 layer = 0; layer < n_layer; layer++) {
		(void)mc_write_str(1, "  layer ");
		mc_write_u64_dec(1, layer);
		(void)mc_write_str(1, "...\n");

		char name[128];
		struct tensor_entry *ln_1_g;
		struct tensor_entry *ln_1_b;
		struct tensor_entry *c_attn_w;
		struct tensor_entry *c_attn_b;
		struct tensor_entry *c_proj_w;
		struct tensor_entry *c_proj_b;
		struct tensor_entry *ln_2_g;
		struct tensor_entry *ln_2_b;
		struct tensor_entry *c_fc_w;
		struct tensor_entry *c_fc_b;
		struct tensor_entry *c_proj2_w;
		struct tensor_entry *c_proj2_b;

		(void)mc_snprint_cstr_cstr_u64_cstr(name, sizeof(name), "model/h", "", layer, "/ln_1/g");
		ln_1_g = find_tensor_by_name(name);
		if (!ln_1_g) die_missing_tensor(argv[0], name);
		(void)mc_snprint_cstr_cstr_u64_cstr(name, sizeof(name), "model/h", "", layer, "/ln_1/b");
		ln_1_b = find_tensor_by_name(name);
		if (!ln_1_b) die_missing_tensor(argv[0], name);
		(void)mc_snprint_cstr_cstr_u64_cstr(name, sizeof(name), "model/h", "", layer, "/attn/c_attn/w");
		c_attn_w = find_tensor_by_name(name);
		if (!c_attn_w) die_missing_tensor(argv[0], name);
		(void)mc_snprint_cstr_cstr_u64_cstr(name, sizeof(name), "model/h", "", layer, "/attn/c_attn/b");
		c_attn_b = find_tensor_by_name(name);
		if (!c_attn_b) die_missing_tensor(argv[0], name);
		(void)mc_snprint_cstr_cstr_u64_cstr(name, sizeof(name), "model/h", "", layer, "/attn/c_proj/w");
		c_proj_w = find_tensor_by_name(name);
		if (!c_proj_w) die_missing_tensor(argv[0], name);
		(void)mc_snprint_cstr_cstr_u64_cstr(name, sizeof(name), "model/h", "", layer, "/attn/c_proj/b");
		c_proj_b = find_tensor_by_name(name);
		if (!c_proj_b) die_missing_tensor(argv[0], name);
		(void)mc_snprint_cstr_cstr_u64_cstr(name, sizeof(name), "model/h", "", layer, "/ln_2/g");
		ln_2_g = find_tensor_by_name(name);
		if (!ln_2_g) die_missing_tensor(argv[0], name);
		(void)mc_snprint_cstr_cstr_u64_cstr(name, sizeof(name), "model/h", "", layer, "/ln_2/b");
		ln_2_b = find_tensor_by_name(name);
		if (!ln_2_b) die_missing_tensor(argv[0], name);
		(void)mc_snprint_cstr_cstr_u64_cstr(name, sizeof(name), "model/h", "", layer, "/mlp/c_fc/w");
		c_fc_w = find_tensor_by_name(name);
		if (!c_fc_w) die_missing_tensor(argv[0], name);
		(void)mc_snprint_cstr_cstr_u64_cstr(name, sizeof(name), "model/h", "", layer, "/mlp/c_fc/b");
		c_fc_b = find_tensor_by_name(name);
		if (!c_fc_b) die_missing_tensor(argv[0], name);
		(void)mc_snprint_cstr_cstr_u64_cstr(name, sizeof(name), "model/h", "", layer, "/mlp/c_proj/w");
		c_proj2_w = find_tensor_by_name(name);
		if (!c_proj2_w) die_missing_tensor(argv[0], name);
		(void)mc_snprint_cstr_cstr_u64_cstr(name, sizeof(name), "model/h", "", layer, "/mlp/c_proj/b");
		c_proj2_b = find_tensor_by_name(name);
		if (!c_proj2_b) die_missing_tensor(argv[0], name);

		if (!tensor_match_1d(ln_1_g, n_embd, ln_size)) mc_die_errno(argv[0], "ln_1_g shape mismatch", -1);
		if (!tensor_match_1d(ln_1_b, n_embd, ln_size)) mc_die_errno(argv[0], "ln_1_b shape mismatch", -1);
		if (!tensor_match_1d(ln_2_g, n_embd, ln_size)) mc_die_errno(argv[0], "ln_2_g shape mismatch", -1);
		if (!tensor_match_1d(ln_2_b, n_embd, ln_size)) mc_die_errno(argv[0], "ln_2_b shape mismatch", -1);
		if (!tensor_match_1d(c_attn_b, 3 * n_embd, c_attn_b_size)) mc_die_errno(argv[0], "c_attn_b shape mismatch", -1);
		if (!tensor_match_1d(c_proj_b, n_embd, ln_size)) mc_die_errno(argv[0], "c_proj_b shape mismatch", -1);
		if (!tensor_match_1d(c_fc_b, 4 * n_embd, c_fc_b_size)) mc_die_errno(argv[0], "c_fc_b shape mismatch", -1);
		if (!tensor_match_1d(c_proj2_b, n_embd, ln_size)) mc_die_errno(argv[0], "c_proj2_b shape mismatch", -1);

		if (write_tensor_raw_checked((mc_i32)out_fd, data_base, data_size, ln_1_g) < 0) mc_die_errno(argv[0], "write ln_1_g", -1);
		if (write_tensor_raw_checked((mc_i32)out_fd, data_base, data_size, ln_1_b) < 0) mc_die_errno(argv[0], "write ln_1_b", -1);
		bytes_written += ln_1_g->size + ln_1_b->size;

		if (qtype == GPT2_QTYPE_F32) {
			if (write_tensor_transposed_mat_checked((mc_i32)out_fd, data_base, data_size, c_attn_w, n_embd, 3 * n_embd) < 0) mc_die_errno(argv[0], "write c_attn_w", -1);
			bytes_written += c_attn_w->size;
		} else {
			if (write_tensor_transposed_quant_checked((mc_i32)out_fd, data_base, data_size, c_attn_w, n_embd, 3 * n_embd, qtype) < 0) mc_die_errno(argv[0], "write c_attn_w quant", -1);
			bytes_written += qmat_storage_bytes(qtype, n_embd, 3 * n_embd);
			write_pad16((mc_i32)out_fd, &bytes_written, "write c_attn_w pad16");
		}
		if (write_tensor_raw_checked((mc_i32)out_fd, data_base, data_size, c_attn_b) < 0) mc_die_errno(argv[0], "write c_attn_b", -1);
		bytes_written += c_attn_b->size;

		if (qtype == GPT2_QTYPE_F32) {
			if (write_tensor_transposed_mat_checked((mc_i32)out_fd, data_base, data_size, c_proj_w, n_embd, n_embd) < 0) mc_die_errno(argv[0], "write c_proj_w", -1);
			bytes_written += c_proj_w->size;
		} else {
			if (write_tensor_transposed_quant_checked((mc_i32)out_fd, data_base, data_size, c_proj_w, n_embd, n_embd, qtype) < 0) mc_die_errno(argv[0], "write c_proj_w quant", -1);
			bytes_written += qmat_storage_bytes(qtype, n_embd, n_embd);
			write_pad16((mc_i32)out_fd, &bytes_written, "write c_proj_w pad16");
		}
		if (write_tensor_raw_checked((mc_i32)out_fd, data_base, data_size, c_proj_b) < 0) mc_die_errno(argv[0], "write c_proj_b", -1);
		bytes_written += c_proj_b->size;

		if (write_tensor_raw_checked((mc_i32)out_fd, data_base, data_size, ln_2_g) < 0) mc_die_errno(argv[0], "write ln_2_g", -1);
		if (write_tensor_raw_checked((mc_i32)out_fd, data_base, data_size, ln_2_b) < 0) mc_die_errno(argv[0], "write ln_2_b", -1);
		bytes_written += ln_2_g->size + ln_2_b->size;

		if (qtype == GPT2_QTYPE_F32) {
			if (write_tensor_transposed_mat_checked((mc_i32)out_fd, data_base, data_size, c_fc_w, n_embd, 4 * n_embd) < 0) mc_die_errno(argv[0], "write c_fc_w", -1);
			bytes_written += c_fc_w->size;
		} else {
			if (write_tensor_transposed_quant_checked((mc_i32)out_fd, data_base, data_size, c_fc_w, n_embd, 4 * n_embd, qtype) < 0) mc_die_errno(argv[0], "write c_fc_w quant", -1);
			bytes_written += qmat_storage_bytes(qtype, n_embd, 4 * n_embd);
			write_pad16((mc_i32)out_fd, &bytes_written, "write c_fc_w pad16");
		}
		if (write_tensor_raw_checked((mc_i32)out_fd, data_base, data_size, c_fc_b) < 0) mc_die_errno(argv[0], "write c_fc_b", -1);
		bytes_written += c_fc_b->size;

		if (qtype == GPT2_QTYPE_F32) {
			if (write_tensor_transposed_mat_checked((mc_i32)out_fd, data_base, data_size, c_proj2_w, 4 * n_embd, n_embd) < 0) mc_die_errno(argv[0], "write c_proj2_w", -1);
			bytes_written += c_proj2_w->size;
		} else {
			if (write_tensor_transposed_quant_checked((mc_i32)out_fd, data_base, data_size, c_proj2_w, 4 * n_embd, n_embd, qtype) < 0) mc_die_errno(argv[0], "write c_proj2_w quant", -1);
			bytes_written += qmat_storage_bytes(qtype, 4 * n_embd, n_embd);
			write_pad16((mc_i32)out_fd, &bytes_written, "write c_proj2_w pad16");
		}
		if (write_tensor_raw_checked((mc_i32)out_fd, data_base, data_size, c_proj2_b) < 0) mc_die_errno(argv[0], "write c_proj2_b", -1);
		bytes_written += c_proj2_b->size;
	}

	/* 4. ln_f (final layer norm) */
	struct tensor_entry *ln_f_g = find_tensor_by_name("model/ln_f/g");
	struct tensor_entry *ln_f_b = find_tensor_by_name("model/ln_f/b");
	if (!ln_f_g) die_missing_tensor(argv[0], "model/ln_f/g");
	if (!ln_f_b) die_missing_tensor(argv[0], "model/ln_f/b");
	if (!tensor_match_1d(ln_f_g, n_embd, ln_size)) mc_die_errno(argv[0], "ln_f_g shape mismatch", -1);
	if (!tensor_match_1d(ln_f_b, n_embd, ln_size)) mc_die_errno(argv[0], "ln_f_b shape mismatch", -1);

	(void)mc_write_str(1, "  ln_f/g: ");
	mc_write_u64_dec(1, ln_f_g->size);
	(void)mc_write_str(1, " bytes\n");
	if (write_tensor_raw_checked((mc_i32)out_fd, data_base, data_size, ln_f_g) < 0) {
		mc_die_errno(argv[0], "write ln_f_g", -1);
	}
	bytes_written += ln_f_g->size;

	(void)mc_write_str(1, "  ln_f/b: ");
	mc_write_u64_dec(1, ln_f_b->size);
	(void)mc_write_str(1, " bytes\n");
	if (write_tensor_raw_checked((mc_i32)out_fd, data_base, data_size, ln_f_b) < 0) {
		mc_die_errno(argv[0], "write ln_f_b", -1);
	}
	bytes_written += ln_f_b->size;

	mc_sys_close((mc_i32)out_fd);

	(void)mc_write_str(1, "\nDone! Wrote ");
	mc_write_u64_dec(1, bytes_written);
	(void)mc_write_str(1, " bytes to ");
	(void)mc_write_str(1, out_path);
	(void)mc_write_str(1, "\n");

	if (bytes_written != expected_total_bytes) {
		(void)mc_write_str(2, "ckpt2bin: size mismatch: wrote ");
		mc_write_u64_dec(2, bytes_written);
		(void)mc_write_str(2, " expected ");
		mc_write_u64_dec(2, expected_total_bytes);
		(void)mc_write_str(2, "\n");
		mc_exit(1);
	}

	return 0;
}

#endif
