/* GPT-2 Inference Engine - No C library, syscalls only
 * Runs GPT-2 117M model for text generation
 */

#include "mc.h"
#include "mc_mathf.h"

static void *map_file(const char *path, mc_usize *out_size);

static void *alloc_anon_rw(mc_usize size);
static mc_i32 alloc_floats(float **out, mc_u64 n);
static mc_i32 alloc_bytes(void **out, mc_u64 n);

/* Model hyperparameters (GPT-2 vocab/ctx are fixed for our tokenizer/runtime) */
#define N_VOCAB   50257
#define N_CTX     1024

/* Maximum generation length */
#define MAX_GEN_TOKENS 100

/* Max prompt tokens in text mode */
#define MAX_PROMPT_TOKENS 1024

/* Sampling candidate cap used for --top-p (and as a fallback for --top-k). */
#define CAND_CAP 512

#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 32

/* ========== Model Data ========== */

static int g_verbose = 0;
static int g_raw = 0;

static int g_max_gen_tokens = 20;
static int g_top_k = 40;           /* classic-ish GPT-2 default */
static float g_temperature = 1.0f; /* classic-ish GPT-2 default */
static float g_top_p = 0.0f;       /* 0 = disabled; (0,1] enables nucleus sampling */
static mc_u32 g_rng_state = 1;
static int g_rng_seeded = 0;

/* Runtime model dimensions (loaded from model header). */
static mc_u32 g_n_embd = 0;
static mc_u32 g_n_head = 0;
static mc_u32 g_n_layer = 0;
static mc_u32 g_n_embd_x2 = 0;
static mc_u32 g_n_embd_x3 = 0;
static mc_u32 g_n_embd_x4 = 0;
static mc_u32 g_ctx_embd = 0;       /* N_CTX * g_n_embd */
static mc_u32 g_kv_cache_size = 0;  /* g_n_layer * N_CTX * g_n_embd */

/* Model weights (mmap'd from file) */
/* For f32 models: wte is [n_vocab, n_embd] floats.
 * For quantized models: wte_q points to an interleaved block of [scale f32][row bytes] per vocab row.
 */
static float *wte;      /* token embeddings: [n_vocab, n_embd] */
static const mc_u8 *wte_q;
static float *wpe;      /* position embeddings: [n_ctx, n_embd] */
static float *ln_f_g;   /* final layernorm gamma: [n_embd] */
static float *ln_f_b;   /* final layernorm beta: [n_embd] */

#define GPT2_QTYPE_F32 0
#define GPT2_QTYPE_Q8  1
#define GPT2_QTYPE_Q4  2

static mc_u32 g_model_qtype = GPT2_QTYPE_F32;

/* Per-layer weights */
typedef struct {
    float *ln1_g;
    float *ln1_b;
    float *attn_qkv_w;        /* QKV projection: [n_embd, 3*n_embd] */
    const mc_u8 *attn_qkv_q;  /* quantized QKV projection, if any */
    float *attn_qkv_b;        /* QKV bias: [3*n_embd] */
    float *attn_proj_w;       /* attention output proj: [n_embd, n_embd] */
    const mc_u8 *attn_proj_q; /* quantized attention proj, if any */
    float *attn_proj_b;       /* attention output proj bias: [n_embd] */
    float *ln2_g;
    float *ln2_b;
    float *mlp_fc_w;          /* MLP fc: [n_embd, 4*n_embd] */
    const mc_u8 *mlp_fc_q;    /* quantized MLP fc, if any */
    float *mlp_fc_b;          /* MLP fc bias: [4*n_embd] */
    float *mlp_proj_w;        /* MLP proj: [4*n_embd, n_embd] */
    const mc_u8 *mlp_proj_q;  /* quantized MLP proj, if any */
    float *mlp_proj_b;        /* MLP proj bias: [n_embd] */
} LayerWeights;

static LayerWeights *layers;

/* Activation buffers (mmap allocation) */
static float *x;               /* current hidden state: [n_embd] */
static float *residual;        /* residual connection: [n_embd] */
static float *ln_out;          /* layer norm output: [n_embd] */
static float *qkv;             /* Q, K, V: [3*n_embd] */
static float *attn_out;        /* attention output: [n_embd] */
static float *attn_tmp;        /* temp: [n_embd] */
static float *mlp_hidden;      /* MLP hidden: [4*n_embd] */
static float *mlp_out;         /* MLP output: [n_embd] */
static float logits[N_VOCAB];         /* output logits */

static float attn_scores[N_CTX];      /* attention scores (reused per head) */

/* KV cache for efficient generation - flattened */
/* Access: k_cache[layer * N_CTX * n_embd + pos * n_embd + i] */
static float *k_cache;
static float *v_cache;

static mc_u32 rng_u32(void)
{
    /* xorshift32 */
    mc_u32 x = g_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    g_rng_state = x;
    return x;
}

static float rng_f01(void)
{
    /* 24-bit mantissa uniform in [0, 1) */
    mc_u32 r = rng_u32();
    mc_u32 m = r & 0xFFFFFFu;
    return (float)m * (1.0f / 16777216.0f);
}

static void rng_seed_if_needed(void)
{
    if (g_rng_seeded) return;
    mc_u32 s = 0;
    mc_i64 r = mc_sys_getrandom(&s, (mc_usize)sizeof(s), 0);
    if (r == (mc_i64)sizeof(s) && s != 0) {
        g_rng_state = s;
    } else {
        g_rng_state = 1;
    }
    g_rng_seeded = 1;
}

static int parse_float_simple(const char *s, float *out)
{
    if (!s || !*s || !out) return -1;
    mc_u64 ip = 0;
    mc_u64 fp = 0;
    mc_u64 fscale = 1;
    int saw_dot = 0;
    int saw_digit = 0;

    for (const char *p = s; *p; p++) {
        if (*p == '.') {
            if (saw_dot) return -1;
            saw_dot = 1;
            continue;
        }
        if (*p < '0' || *p > '9') return -1;
        saw_digit = 1;
        mc_u64 d = (mc_u64)(*p - '0');
        if (!saw_dot) {
            ip = ip * 10u + d;
        } else {
            if (fscale < 1000000u) {
                fp = fp * 10u + d;
                fscale *= 10u;
            }
        }
    }
    if (!saw_digit) return -1;

    *out = (float)ip + (fscale > 1 ? ((float)fp / (float)fscale) : 0.0f);
    return 0;
}

/* ========== Tokenizer (Byte-level BPE) ========== */

#define MAX_VOCAB     50257
#define MAX_MERGES    50000
#define MAX_TOKEN_LEN 256

/* Hash tables: open addressing with linear probing */
#define TOK_HASH_SIZE 131071u /* prime-ish */
#define MERGE_HASH_SIZE 262139u

typedef struct {
    mc_u32 vocab_index; /* index into vocab[] */
    mc_u8 used;
} TokHashEnt;

typedef struct {
    mc_u32 merge_index; /* index into merges[] */
    mc_u8 used;
} MergeHashEnt;

typedef struct {
    mc_u8   bytes[MAX_TOKEN_LEN];
    mc_u32  len;
    mc_u32  id;
} Token;

typedef struct {
    mc_u8   first[MAX_TOKEN_LEN];
    mc_u32  first_len;
    mc_u8   second[MAX_TOKEN_LEN];
    mc_u32  second_len;
    mc_u32  rank;  /* lower = higher priority */
} Merge;

static Token vocab[MAX_VOCAB];
static mc_u32 vocab_count;
static Merge merges[MAX_MERGES];
static mc_u32 merge_count;

static TokHashEnt tok_hash[TOK_HASH_SIZE];
static MergeHashEnt merge_hash[MERGE_HASH_SIZE];

static mc_i32 id_to_vocab_index[MAX_VOCAB];

/* Byte encoder table: GPT-2 maps bytes 0-255 to printable chars */
static mc_u16 byte_encoder[256];
static mc_u8  byte_decoder[512];

static int g_tokenizer_ready = 0;

static mc_u32 fnv1a32(const mc_u8 *p, mc_u32 n)
{
    mc_u32 h = 2166136261u;
    for (mc_u32 i = 0; i < n; i++) {
        h ^= (mc_u32)p[i];
        h *= 16777619u;
    }
    return h;
}

static void tok_hash_clear(void)
{
    for (mc_u32 i = 0; i < TOK_HASH_SIZE; i++) {
        tok_hash[i].used = 0;
        tok_hash[i].vocab_index = 0;
    }
}

static void merge_hash_clear(void)
{
    for (mc_u32 i = 0; i < MERGE_HASH_SIZE; i++) {
        merge_hash[i].used = 0;
        merge_hash[i].merge_index = 0;
    }
}

static void id_index_clear(void)
{
    for (mc_u32 i = 0; i < MAX_VOCAB; i++) id_to_vocab_index[i] = -1;
}

static void init_byte_encoder(void)
{
    for (mc_u32 i = 0; i < 256; i++) byte_encoder[i] = 0;
    for (mc_u32 i = 0; i < 512; i++) byte_decoder[i] = 0;

    /* Printable ASCII: ! to ~ */
    for (mc_u32 i = 33; i <= 126; i++) {
        byte_encoder[i] = (mc_u16)i;
        byte_decoder[i] = (mc_u8)i;
    }
    /* Latin-1 supplement printable */
    for (mc_u32 i = 161; i <= 172; i++) {
        byte_encoder[i] = (mc_u16)i;
        byte_decoder[i] = (mc_u8)i;
    }
    for (mc_u32 i = 174; i <= 255; i++) {
        byte_encoder[i] = (mc_u16)i;
        byte_decoder[i] = (mc_u8)i;
    }

    mc_u32 next = 256;
    for (mc_u32 i = 0; i < 256; i++) {
        if (byte_encoder[i] == 0) {
            byte_encoder[i] = (mc_u16)next;
            byte_decoder[next] = (mc_u8)i;
            next++;
        }
    }
}

/* Decode a JSON string escape sequence; returns bytes consumed or 0 on error */
static mc_u32 decode_json_escape(const mc_u8 *s, mc_u8 *out, mc_u32 *out_len)
{
    if (s[0] != '\\') {
        if (*out_len < MAX_TOKEN_LEN) {
            out[*out_len] = s[0];
            (*out_len)++;
        }
        return 1;
    }

    switch (s[1]) {
    case '"':
        if (*out_len < MAX_TOKEN_LEN) {
            out[*out_len] = '"';
            (*out_len)++;
        }
        return 2;
    case '\\':
        if (*out_len < MAX_TOKEN_LEN) {
            out[*out_len] = '\\';
            (*out_len)++;
        }
        return 2;
    case '/':
        if (*out_len < MAX_TOKEN_LEN) {
            out[*out_len] = '/';
            (*out_len)++;
        }
        return 2;
    case 'b':
        if (*out_len < MAX_TOKEN_LEN) {
            out[*out_len] = '\b';
            (*out_len)++;
        }
        return 2;
    case 'f':
        if (*out_len < MAX_TOKEN_LEN) {
            out[*out_len] = '\f';
            (*out_len)++;
        }
        return 2;
    case 'n':
        if (*out_len < MAX_TOKEN_LEN) {
            out[*out_len] = '\n';
            (*out_len)++;
        }
        return 2;
    case 'r':
        if (*out_len < MAX_TOKEN_LEN) {
            out[*out_len] = '\r';
            (*out_len)++;
        }
        return 2;
    case 't':
        if (*out_len < MAX_TOKEN_LEN) {
            out[*out_len] = '\t';
            (*out_len)++;
        }
        return 2;
    case 'u': {
        mc_u32 cp = 0;
        for (mc_u32 i = 0; i < 4; i++) {
            mc_u8 c = s[2 + i];
            mc_u32 v;
            if (c >= '0' && c <= '9') v = (mc_u32)(c - '0');
            else if (c >= 'a' && c <= 'f') v = 10u + (mc_u32)(c - 'a');
            else if (c >= 'A' && c <= 'F') v = 10u + (mc_u32)(c - 'A');
            else return 0;
            cp = (cp << 4) | v;
        }

        /* Encode as UTF-8 */
        if (cp < 0x80) {
            if (*out_len < MAX_TOKEN_LEN) {
                out[*out_len] = (mc_u8)cp;
                (*out_len)++;
            }
        } else if (cp < 0x800) {
            mc_u8 a = (mc_u8)(0xC0 | (cp >> 6));
            mc_u8 b = (mc_u8)(0x80 | (cp & 0x3F));
            if (*out_len < MAX_TOKEN_LEN) {
                out[*out_len] = a;
                (*out_len)++;
            }
            if (*out_len < MAX_TOKEN_LEN) {
                out[*out_len] = b;
                (*out_len)++;
            }
        } else {
            mc_u8 a = (mc_u8)(0xE0 | (cp >> 12));
            mc_u8 b = (mc_u8)(0x80 | ((cp >> 6) & 0x3F));
            mc_u8 c = (mc_u8)(0x80 | (cp & 0x3F));
            if (*out_len < MAX_TOKEN_LEN) {
                out[*out_len] = a;
                (*out_len)++;
            }
            if (*out_len < MAX_TOKEN_LEN) {
                out[*out_len] = b;
                (*out_len)++;
            }
            if (*out_len < MAX_TOKEN_LEN) {
                out[*out_len] = c;
                (*out_len)++;
            }
        }
        return 6;
    }
    default:
        if (*out_len < MAX_TOKEN_LEN) {
            out[*out_len] = s[1];
            (*out_len)++;
        }
        return 2;
    }
}

static mc_u32 bytes_equal(const mc_u8 *a, mc_u32 alen, const mc_u8 *b, mc_u32 blen)
{
    if (alen != blen) return 0;
    for (mc_u32 i = 0; i < alen; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static mc_i32 tok_hash_put(mc_u32 vocab_index)
{
    Token *t = &vocab[vocab_index];
    mc_u32 h = fnv1a32(t->bytes, t->len);
    mc_u32 pos = h % TOK_HASH_SIZE;
    for (mc_u32 i = 0; i < TOK_HASH_SIZE; i++) {
        mc_u32 idx = (pos + i) % TOK_HASH_SIZE;
        if (!tok_hash[idx].used) {
            tok_hash[idx].used = 1;
            tok_hash[idx].vocab_index = vocab_index;
            return 0;
        }
    }
    return -1;
}

static mc_i32 tok_hash_get_id(const mc_u8 *bytes, mc_u32 len)
{
    mc_u32 h = fnv1a32(bytes, len);
    mc_u32 pos = h % TOK_HASH_SIZE;
    for (mc_u32 i = 0; i < TOK_HASH_SIZE; i++) {
        mc_u32 idx = (pos + i) % TOK_HASH_SIZE;
        if (!tok_hash[idx].used) return -1;
        Token *t = &vocab[tok_hash[idx].vocab_index];
        if (bytes_equal(bytes, len, t->bytes, t->len)) return (mc_i32)t->id;
    }
    return -1;
}

static mc_u32 merge_key_hash(const mc_u8 *a, mc_u32 alen, const mc_u8 *b, mc_u32 blen)
{
    mc_u32 h = 2166136261u;
    h = fnv1a32(a, alen) ^ (h * 16777619u);
    h ^= 0xFFu;
    h *= 16777619u;
    h ^= fnv1a32(b, blen);
    h *= 16777619u;
    h ^= (alen << 16) ^ blen;
    return h;
}

static mc_i32 merge_hash_put(mc_u32 merge_index)
{
    Merge *m = &merges[merge_index];
    mc_u32 h = merge_key_hash(m->first, m->first_len, m->second, m->second_len);
    mc_u32 pos = h % MERGE_HASH_SIZE;
    for (mc_u32 i = 0; i < MERGE_HASH_SIZE; i++) {
        mc_u32 idx = (pos + i) % MERGE_HASH_SIZE;
        if (!merge_hash[idx].used) {
            merge_hash[idx].used = 1;
            merge_hash[idx].merge_index = merge_index;
            return 0;
        }
    }
    return -1;
}

static mc_i32 merge_hash_get_rank(const mc_u8 *a, mc_u32 alen, const mc_u8 *b, mc_u32 blen)
{
    mc_u32 h = merge_key_hash(a, alen, b, blen);
    mc_u32 pos = h % MERGE_HASH_SIZE;
    for (mc_u32 i = 0; i < MERGE_HASH_SIZE; i++) {
        mc_u32 idx = (pos + i) % MERGE_HASH_SIZE;
        if (!merge_hash[idx].used) return -1;
        Merge *m = &merges[merge_hash[idx].merge_index];
        if (m->first_len == alen && m->second_len == blen &&
            bytes_equal(a, alen, m->first, m->first_len) &&
            bytes_equal(b, blen, m->second, m->second_len)) {
            return (mc_i32)m->rank;
        }
    }
    return -1;
}

static mc_i32 load_encoder_json(const char *path)
{
    mc_usize size;
    mc_u8 *data = (mc_u8 *)map_file(path, &size);
    if (!data) {
        (void)mc_write_str(2, "Error: cannot open encoder.json\n");
        return -1;
    }

    vocab_count = 0;
    mc_u64 pos = 0;

    while (pos < (mc_u64)size && data[pos] != '{') pos++;
    if (pos >= (mc_u64)size) {
        mc_sys_munmap(data, size);
        (void)mc_write_str(2, "Error: invalid encoder.json\n");
        return -1;
    }
    pos++;

    while (pos < (mc_u64)size && vocab_count < MAX_VOCAB) {
        while (pos < (mc_u64)size && (data[pos] == ' ' || data[pos] == '\n' || data[pos] == '\r' || data[pos] == '\t' || data[pos] == ',')) pos++;
        if (pos >= (mc_u64)size || data[pos] == '}') break;

        if (data[pos] != '"') {
            (void)mc_write_str(2, "Error: expected \" in encoder.json\n");
            break;
        }
        pos++;

        Token *t = &vocab[vocab_count];
        t->len = 0;

        while (pos < (mc_u64)size && data[pos] != '"') {
            mc_u32 consumed = decode_json_escape(&data[pos], t->bytes, &t->len);
            if (consumed == 0) {
                (void)mc_write_str(2, "Error: invalid escape in encoder.json\n");
                break;
            }
            pos += consumed;
        }
        if (pos < (mc_u64)size && data[pos] == '"') pos++;

        while (pos < (mc_u64)size && data[pos] != ':') pos++;
        if (pos < (mc_u64)size) pos++;
        while (pos < (mc_u64)size && data[pos] == ' ') pos++;

        mc_u32 id = 0;
        while (pos < (mc_u64)size && data[pos] >= '0' && data[pos] <= '9') {
            id = id * 10 + (mc_u32)(data[pos] - '0');
            pos++;
        }

        t->id = id;
        if (id < MAX_VOCAB) id_to_vocab_index[id] = (mc_i32)vocab_count;
        if (tok_hash_put(vocab_count) < 0) {
            (void)mc_write_str(2, "Error: token hash table full\n");
            mc_sys_munmap(data, size);
            return -1;
        }
        vocab_count++;
    }

    mc_sys_munmap(data, size);

    if (g_verbose) {
        (void)mc_write_str(1, "Loaded ");
        mc_write_u64_dec(1, vocab_count);
        (void)mc_write_str(1, " tokens from encoder.json\n");
    }
    return 0;
}

static mc_i32 load_merges_bpe(const char *path)
{
    mc_usize size;
    mc_u8 *data = (mc_u8 *)map_file(path, &size);
    if (!data) {
        (void)mc_write_str(2, "Error: cannot open vocab.bpe\n");
        return -1;
    }

    merge_count = 0;
    mc_u64 pos = 0;
    mc_u32 line = 0;

    while (pos < (mc_u64)size && merge_count < MAX_MERGES) {
        mc_u64 line_start = pos;
        while (pos < (mc_u64)size && data[pos] != '\n') pos++;
        mc_u64 line_end = pos;
        if (pos < (mc_u64)size) pos++;
        line++;
        if (line == 1) continue;
        if (line_end == line_start) continue;

        Merge *m = &merges[merge_count];
        m->first_len = 0;
        m->second_len = 0;
        m->rank = merge_count;

        mc_u64 p = line_start;
        while (p < line_end && data[p] != ' ') {
            if (m->first_len < MAX_TOKEN_LEN) m->first[m->first_len] = data[p];
            m->first_len++;
            p++;
        }
        if (p < line_end && data[p] == ' ') p++;
        while (p < line_end) {
            if (m->second_len < MAX_TOKEN_LEN) m->second[m->second_len] = data[p];
            m->second_len++;
            p++;
        }

        if (m->first_len > 0 && m->second_len > 0 && m->first_len <= MAX_TOKEN_LEN && m->second_len <= MAX_TOKEN_LEN) {
            if (merge_hash_put(merge_count) < 0) {
                (void)mc_write_str(2, "Error: merge hash table full\n");
                mc_sys_munmap(data, size);
                return -1;
            }
            merge_count++;
        }
    }

    mc_sys_munmap(data, size);

    if (g_verbose) {
        (void)mc_write_str(1, "Loaded ");
        mc_write_u64_dec(1, merge_count);
        (void)mc_write_str(1, " merges from vocab.bpe\n");
    }
    return 0;
}

typedef struct {
    mc_u8 bytes[MAX_TOKEN_LEN];
    mc_u32 len;
} BPEToken;

typedef struct {
    BPEToken tokens[96]; /* bounded so a merged token never exceeds MAX_TOKEN_LEN */
    mc_u32 count;
} BPESequence;

static void bpe_text_to_tokens(const mc_u8 *text, mc_u32 text_len, BPESequence *seq)
{
    seq->count = 0;
    for (mc_u32 i = 0; i < text_len && seq->count < (mc_u32)(sizeof(seq->tokens) / sizeof(seq->tokens[0])); i++) {
        mc_u8 b = text[i];
        mc_u16 cp = byte_encoder[b];
        BPEToken *t = &seq->tokens[seq->count];
        t->len = 0;
        if (cp < 0x80) {
            t->bytes[t->len++] = (mc_u8)cp;
        } else if (cp < 0x800) {
            t->bytes[t->len++] = (mc_u8)(0xC0 | (cp >> 6));
            t->bytes[t->len++] = (mc_u8)(0x80 | (cp & 0x3F));
        } else {
            t->bytes[t->len++] = (mc_u8)(0xE0 | (cp >> 12));
            t->bytes[t->len++] = (mc_u8)(0x80 | ((cp >> 6) & 0x3F));
            t->bytes[t->len++] = (mc_u8)(0x80 | (cp & 0x3F));
        }
        seq->count++;
    }
}

static mc_i32 bpe_find_best_merge(BPESequence *seq, mc_u32 *best_i)
{
    mc_i32 best_rank = -1;
    for (mc_u32 i = 0; i + 1 < seq->count; i++) {
        BPEToken *a = &seq->tokens[i];
        BPEToken *b = &seq->tokens[i + 1];
        mc_i32 rank = merge_hash_get_rank(a->bytes, a->len, b->bytes, b->len);
        if (rank >= 0) {
            if (best_rank < 0 || rank < best_rank) {
                best_rank = rank;
                *best_i = i;
            }
        }
    }
    return best_rank;
}

static void bpe_apply_merge(BPESequence *seq, mc_u32 i)
{
    if (i + 1 >= seq->count) return;
    BPEToken *a = &seq->tokens[i];
    BPEToken *b = &seq->tokens[i + 1];

    if (a->len + b->len > MAX_TOKEN_LEN) {
        return;
    }
    for (mc_u32 j = 0; j < b->len; j++) a->bytes[a->len++] = b->bytes[j];
    for (mc_u32 j = i + 1; j + 1 < seq->count; j++) seq->tokens[j] = seq->tokens[j + 1];
    seq->count--;
}

static mc_u32 encode_piece_to_ids(const mc_u8 *text, mc_u32 text_len, mc_u32 *out_ids, mc_u32 out_max)
{
    BPESequence seq;
    bpe_text_to_tokens(text, text_len, &seq);

    while (1) {
        mc_u32 best_i = 0;
        mc_i32 best_rank = bpe_find_best_merge(&seq, &best_i);
        if (best_rank < 0) break;
        bpe_apply_merge(&seq, best_i);
    }

    mc_u32 n = 0;
    for (mc_u32 i = 0; i < seq.count && n < out_max; i++) {
        BPEToken *t = &seq.tokens[i];
        mc_i32 id = tok_hash_get_id(t->bytes, t->len);
        if (id >= 0) {
            out_ids[n++] = (mc_u32)id;
        } else {
            if (g_verbose) (void)mc_write_str(2, "Warning: unknown token\n");
        }
    }
    return n;
}

static int is_space_byte(mc_u8 c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static mc_u32 encode_text_to_ids(const mc_u8 *text, mc_u32 text_len, mc_u32 *out_ids, mc_u32 out_max)
{
    /* Segment into runs of whitespace vs non-whitespace to avoid cross-boundary merges. */
    mc_u32 out_n = 0;
    mc_u32 i = 0;
    while (i < text_len && out_n < out_max) {
        int ws = is_space_byte(text[i]);
        mc_u32 start = i;
        while (i < text_len && is_space_byte(text[i]) == ws) i++;
        mc_u32 seg_len = i - start;

        /* Process in chunks bounded so any merged token fits MAX_TOKEN_LEN.
           Worst-case byte->UTF8 expands to 3 bytes, so cap chunk to 80 bytes. */
        mc_u32 seg_pos = 0;
        while (seg_pos < seg_len && out_n < out_max) {
            mc_u32 chunk = seg_len - seg_pos;
            if (chunk > 80) chunk = 80;
            out_n += encode_piece_to_ids(text + start + seg_pos, chunk, out_ids + out_n, out_max - out_n);
            seg_pos += chunk;
        }
    }
    return out_n;
}

static mc_u32 decode_id_to_bytes(mc_u32 id, mc_u8 *out, mc_u32 out_max)
{
    if (id >= MAX_VOCAB) return 0;
    mc_i32 idx = id_to_vocab_index[id];
    if (idx < 0) return 0;
    Token *t = &vocab[(mc_u32)idx];
    mc_u32 out_len = 0;

    for (mc_u32 j = 0; j < t->len && out_len < out_max; j++) {
        mc_u8 b = t->bytes[j];
        if (b >= 0xC0 && j + 1 < t->len) {
            mc_u32 cp;
            mc_u32 consumed = 1;
            if ((b & 0xE0) == 0xC0 && j + 1 < t->len) {
                cp = ((mc_u32)(b & 0x1F) << 6) | (mc_u32)(t->bytes[j + 1] & 0x3F);
                consumed = 2;
            } else if ((b & 0xF0) == 0xE0 && j + 2 < t->len) {
                cp = ((mc_u32)(b & 0x0F) << 12) | ((mc_u32)(t->bytes[j + 1] & 0x3F) << 6) | (mc_u32)(t->bytes[j + 2] & 0x3F);
                consumed = 3;
            } else {
                cp = (mc_u32)b;
            }
            if (cp < 512) out[out_len++] = byte_decoder[cp];
            j += consumed - 1;
        } else {
            out[out_len++] = byte_decoder[b];
        }
    }
    return out_len;
}

static mc_i32 tokenizer_init_from_dir(const char *dir)
{
    char encoder_path[512];
    char vocab_path[512];
    mc_u32 dir_len = (mc_u32)mc_strlen(dir);
    if (dir_len + 1 + 13 >= sizeof(encoder_path) || dir_len + 1 + 10 >= sizeof(vocab_path)) {
        (void)mc_write_str(2, "Error: tokenizer dir path too long\n");
        return -1;
    }

    mc_memcpy(encoder_path, dir, dir_len);
    encoder_path[dir_len] = '/';
    mc_memcpy(encoder_path + dir_len + 1, "encoder.json", 13);
    encoder_path[dir_len + 1 + 12] = 0;

    mc_memcpy(vocab_path, dir, dir_len);
    vocab_path[dir_len] = '/';
    mc_memcpy(vocab_path + dir_len + 1, "vocab.bpe", 10);
    vocab_path[dir_len + 1 + 9] = 0;

    init_byte_encoder();
    tok_hash_clear();
    merge_hash_clear();
    id_index_clear();

    if (load_encoder_json(encoder_path) < 0) return -1;
    if (load_merges_bpe(vocab_path) < 0) return -1;

    g_tokenizer_ready = 1;
    return 0;
}

/* ========== Layer Operations ========== */

/* KV cache index calculation */
static int kv_idx(int layer, int pos, int i)
{
    return (int)((mc_u32)layer * g_ctx_embd + (mc_u32)pos * g_n_embd + (mc_u32)i);
}

static mc_i32 alloc_runtime_buffers(void)
{
    if (g_n_embd == 0 || g_n_head == 0 || g_n_layer == 0) return -1;
    if (g_n_embd_x3 != 3u * g_n_embd || g_n_embd_x4 != 4u * g_n_embd) return -1;

    if (alloc_bytes((void **)&layers, (mc_u64)g_n_layer * (mc_u64)sizeof(LayerWeights)) < 0) return -1;
    if (alloc_floats(&x, (mc_u64)g_n_embd) < 0) return -1;
    if (alloc_floats(&residual, (mc_u64)g_n_embd) < 0) return -1;
    if (alloc_floats(&ln_out, (mc_u64)g_n_embd) < 0) return -1;
    if (alloc_floats(&qkv, (mc_u64)g_n_embd_x3) < 0) return -1;
    if (alloc_floats(&attn_out, (mc_u64)g_n_embd) < 0) return -1;
    if (alloc_floats(&attn_tmp, (mc_u64)g_n_embd) < 0) return -1;
    if (alloc_floats(&mlp_hidden, (mc_u64)g_n_embd_x4) < 0) return -1;
    if (alloc_floats(&mlp_out, (mc_u64)g_n_embd) < 0) return -1;

    mc_u64 kv_count = (mc_u64)g_kv_cache_size;
    if (kv_count == 0) return -1;
    if (alloc_floats(&k_cache, kv_count) < 0) return -1;
    if (alloc_floats(&v_cache, kv_count) < 0) return -1;

    return 0;
}

/* Layer normalization */
static void layernorm(float *out, const float *inp, const float *gamma, 
                      const float *beta, int n)
{
    /* Compute mean */
    float mean = 0.0f;
    for (int i = 0; i < n; i++) mean += inp[i];
    mean /= n;
    
    /* Compute variance */
    float var = 0.0f;
    for (int i = 0; i < n; i++) {
        float diff = inp[i] - mean;
        var += diff * diff;
    }
    var /= n;
    
    /* Normalize */
    float inv_std = 1.0f / mc_sqrtf(var + 1e-5f);
    for (int i = 0; i < n; i++) {
        out[i] = gamma[i] * (inp[i] - mean) * inv_std + beta[i];
    }
}

/* GELU activation: 0.5 * x * (1 + tanh(sqrt(2/pi) * (x + 0.044715 * x^3))) */
static float gelu(float x)
{
    float c = 0.7978845608f;  /* sqrt(2/pi) */
    float inner = c * (x + 0.044715f * x * x * x);
    return 0.5f * x * (1.0f + mc_tanhf(inner));
}

/* Matrix-vector multiply: out = W @ inp + bias */
/* W is [out_dim, in_dim] stored row-major */
static void matmul(float *out, const float *inp, const float *W, 
                   const float *bias, int out_dim, int in_dim)
{
    for (int i = 0; i < out_dim; i++) {
        float sum = bias ? bias[i] : 0.0f;
        const float *row = W + i * in_dim;
        for (int j = 0; j < in_dim; j++) {
            sum += row[j] * inp[j];
        }
        out[i] = sum;
    }
}

static mc_u32 q_row_bytes(int qtype, int in_dim)
{
    if (qtype == GPT2_QTYPE_Q8) return (mc_u32)in_dim;
    if (qtype == GPT2_QTYPE_Q4) return (mc_u32)((in_dim + 1) / 2);
    return (mc_u32)(in_dim * 4);
}

static float load_f32_bytes(const mc_u8 *p)
{
    float f;
    mc_memcpy(&f, p, 4);
    return f;
}

static int q8_to_i(mc_u8 b)
{
    /* Manual sign-extension for int8 stored in a byte. */
    return (b & 0x80u) ? ((int)b - 256) : (int)b;
}

/* Quantized matrix layout: for each out row i:
 *   f32 scale
 *   row bytes (q8: in_dim bytes; q4: ceil(in_dim/2) bytes)
 */
static void matmul_q8(float *out, const float *inp, const mc_u8 *Wq,
                      const float *bias, int out_dim, int in_dim)
{
    mc_u32 row_bytes = (mc_u32)in_dim;
    mc_u32 stride = 4u + row_bytes;
    for (int i = 0; i < out_dim; i++) {
        const mc_u8 *rowp = Wq + (mc_u32)i * stride;
        float s = load_f32_bytes(rowp);
        const mc_u8 *q = rowp + 4;
        float dot = 0.0f;
        for (int j = 0; j < in_dim; j++) {
            dot += (float)q8_to_i(q[j]) * inp[j];
        }
        float sum = bias ? bias[i] : 0.0f;
        out[i] = sum + s * dot;
    }
}

static void matmul_q4(float *out, const float *inp, const mc_u8 *Wq,
                      const float *bias, int out_dim, int in_dim)
{
    mc_u32 row_bytes = (mc_u32)((in_dim + 1) / 2);
    mc_u32 stride = 4u + row_bytes;
    for (int i = 0; i < out_dim; i++) {
        const mc_u8 *rowp0 = Wq + (mc_u32)i * stride;
        float s = load_f32_bytes(rowp0);
        const mc_u8 *rowp = rowp0 + 4;
        float dot = 0.0f;
        for (int j = 0; j < in_dim; j++) {
            mc_u8 byte = rowp[(mc_u32)j >> 1];
            mc_u8 nib = ((j & 1) == 0) ? (byte & 0xFu) : (byte >> 4);
            int qi = (nib & 0x8u) ? ((int)nib - 16) : (int)nib;
            dot += (float)qi * inp[j];
        }
        float sum = bias ? bias[i] : 0.0f;
        out[i] = sum + s * dot;
    }
}

static void matmul_model(float *out, const float *inp, const float *Wf, const mc_u8 *Wq,
                         const float *bias, int out_dim, int in_dim)
{
    if (g_model_qtype == GPT2_QTYPE_F32) {
        matmul(out, inp, Wf, bias, out_dim, in_dim);
        return;
    }
    if (g_model_qtype == GPT2_QTYPE_Q8) {
        matmul_q8(out, inp, Wq, bias, out_dim, in_dim);
        return;
    }
    matmul_q4(out, inp, Wq, bias, out_dim, in_dim);
}

/* Softmax over array */
static void softmax(float *x, int n)
{
    float max_val = x[0];
    for (int i = 1; i < n; i++) {
        if (x[i] > max_val) max_val = x[i];
    }
    
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        x[i] = mc_expf(x[i] - max_val);
        sum += x[i];
    }
    
    float inv_sum = 1.0f / sum;
    for (int i = 0; i < n; i++) {
        x[i] *= inv_sum;
    }
}

/* Multi-head self-attention for single position */
static void attention(float *out, int layer, int pos)
{
    LayerWeights *l = &layers[layer];
    int head_dim = (int)(g_n_embd / g_n_head);
    
    /* Compute Q, K, V for current position */
    matmul_model(qkv, ln_out, l->attn_qkv_w, l->attn_qkv_q, l->attn_qkv_b, (int)g_n_embd_x3, (int)g_n_embd);
    
    /* Debug: check qkv */
    if (g_verbose && layer == 0 && pos == 0) {
        (void)mc_write_str(1, "qkv[0..4]: ");
        for (int i = 0; i < 5; i++) {
            if (qkv[i] < 0) (void)mc_write_str(1, "-");
            mc_write_u64_dec(1, (mc_u64)(qkv[i] < 0 ? -qkv[i] * 10000 : qkv[i] * 10000));
            (void)mc_write_str(1, " ");
        }
        (void)mc_write_str(1, "\n");
    }
    
    /* Store K, V in cache */
    for (mc_u32 i = 0; i < g_n_embd; i++) {
        k_cache[kv_idx(layer, pos, (int)i)] = qkv[g_n_embd + i];      /* K */
        v_cache[kv_idx(layer, pos, (int)i)] = qkv[g_n_embd_x2 + i];  /* V */
    }
    
    /* Debug: check k_cache */
    if (g_verbose && layer == 0 && pos == 0) {
        (void)mc_write_str(1, "k_cache[0,0,0..4]: ");
        for (int i = 0; i < 5; i++) {
            float kval = k_cache[kv_idx(layer, pos, i)];
            if (kval < 0) (void)mc_write_str(1, "-");
            mc_write_u64_dec(1, (mc_u64)(kval < 0 ? -kval * 10000 : kval * 10000));
            (void)mc_write_str(1, " ");
        }
        (void)mc_write_str(1, "\n");
        (void)mc_write_str(1, "q[0..4]: ");
        for (int i = 0; i < 5; i++) {
            float qval = qkv[i];
            if (qval < 0) (void)mc_write_str(1, "-");
            mc_write_u64_dec(1, (mc_u64)(qval < 0 ? -qval * 10000 : qval * 10000));
            (void)mc_write_str(1, " ");
        }
        (void)mc_write_str(1, "\n");
    }
    
    /* Attention for each head */
    for (mc_u32 h = 0; h < g_n_head; h++) {
        int offset = h * head_dim;
        float *q = qkv + offset;
        
        /* Compute attention scores for this head */
        float scale = 1.0f / mc_sqrtf((float)head_dim);
        
        for (int t = 0; t <= pos; t++) {
            float score = 0.0f;
            for (int i = 0; i < head_dim; i++) {
                score += q[i] * k_cache[kv_idx(layer, t, offset + i)];
            }
            attn_scores[t] = score * scale;
            
            /* Debug: score computation */
            if (g_verbose && layer == 0 && pos == 0 && h == 0 && t == 0) {
                (void)mc_write_str(1, "score raw: ");
                if (score < 0) (void)mc_write_str(1, "-");
                mc_write_u64_dec(1, (mc_u64)(score < 0 ? -score * 100 : score * 100));
                (void)mc_write_str(1, " scale: ");
                mc_write_u64_dec(1, (mc_u64)(scale * 10000));
                (void)mc_write_str(1, "\n");
            }
        }
        
        /* Debug: check scores before softmax */
        if (g_verbose && layer == 0 && pos == 0 && h == 0) {
            (void)mc_write_str(1, "scores[0] before softmax: ");
            if (attn_scores[0] < 0) (void)mc_write_str(1, "-");
            mc_write_u64_dec(1, (mc_u64)(attn_scores[0] < 0 ? -attn_scores[0] * 10000 : attn_scores[0] * 10000));
            (void)mc_write_str(1, "\n");
        }
        
        /* Softmax over positions 0..pos */
        softmax(attn_scores, pos + 1);
        
        /* Debug: check scores after softmax */
        if (g_verbose && layer == 0 && pos == 0 && h == 0) {
            (void)mc_write_str(1, "scores[0] after softmax: ");
            if (attn_scores[0] < 0) (void)mc_write_str(1, "-");
            mc_write_u64_dec(1, (mc_u64)(attn_scores[0] < 0 ? -attn_scores[0] * 10000 : attn_scores[0] * 10000));
            (void)mc_write_str(1, " v_cache[0]: ");
            float v0 = v_cache[kv_idx(layer, 0, offset)];
            if (v0 < 0) (void)mc_write_str(1, "-");
            mc_write_u64_dec(1, (mc_u64)(v0 < 0 ? -v0 * 10000 : v0 * 10000));
            (void)mc_write_str(1, "\n");
        }
        
        /* Weighted sum of values */
        for (int i = 0; i < head_dim; i++) {
            float sum = 0.0f;
            for (int t = 0; t <= pos; t++) {
                sum += attn_scores[t] * v_cache[kv_idx(layer, t, offset + i)];
            }
            attn_tmp[offset + i] = sum;
        }
    }
    
    /* Debug: check attn_tmp before projection */
    if (g_verbose && layer == 0 && pos == 0) {
        (void)mc_write_str(1, "attn_tmp before proj[0..4]: ");
        for (int i = 0; i < 5; i++) {
            if (attn_tmp[i] < 0) (void)mc_write_str(1, "-");
            mc_write_u64_dec(1, (mc_u64)(attn_tmp[i] < 0 ? -attn_tmp[i] * 10000 : attn_tmp[i] * 10000));
            (void)mc_write_str(1, " ");
        }
        (void)mc_write_str(1, "\n");
    }
    
    /* Output projection */
    matmul_model(out, attn_tmp, l->attn_proj_w, l->attn_proj_q, l->attn_proj_b, (int)g_n_embd, (int)g_n_embd);
    
    /* Debug: check projection weights */
    if (g_verbose && layer == 0 && pos == 0) {
        (void)mc_write_str(1, "attn_proj_w[0..4]: ");
        for (int i = 0; i < 5; i++) {
            float wval;
            if (g_model_qtype == GPT2_QTYPE_F32) {
                wval = l->attn_proj_w[i];
            } else if (g_model_qtype == GPT2_QTYPE_Q8) {
                const mc_u8 *rowp0 = l->attn_proj_q;
                float s = load_f32_bytes(rowp0);
                const mc_u8 *q = rowp0 + 4;
                wval = (float)q8_to_i(q[i]) * s;
            } else {
                const mc_u8 *rowp0 = l->attn_proj_q;
                float s = load_f32_bytes(rowp0);
                const mc_u8 *rowp = rowp0 + 4;
                mc_u8 byte = rowp[(mc_u32)i >> 1];
                mc_u8 nib = ((i & 1) == 0) ? (byte & 0xFu) : (byte >> 4);
                int qi = (nib & 0x8u) ? ((int)nib - 16) : (int)nib;
                wval = (float)qi * s;
            }
            if (wval < 0) (void)mc_write_str(1, "-");
            mc_write_u64_dec(1, (mc_u64)(wval < 0 ? -wval * 10000 : wval * 10000));
            (void)mc_write_str(1, " ");
        }
        (void)mc_write_str(1, "\n");
        (void)mc_write_str(1, "attn_proj_b[0..4]: ");
        for (int i = 0; i < 5; i++) {
            float bval = l->attn_proj_b[i];
            if (bval < 0) (void)mc_write_str(1, "-");
            mc_write_u64_dec(1, (mc_u64)(bval < 0 ? -bval * 10000 : bval * 10000));
            (void)mc_write_str(1, " ");
        }
        (void)mc_write_str(1, "\n");
    }
}

/* MLP block */
static void mlp(float *out, const float *inp, int layer)
{
    LayerWeights *l = &layers[layer];
    
    /* FC layer */
    matmul_model(mlp_hidden, inp, l->mlp_fc_w, l->mlp_fc_q, l->mlp_fc_b, (int)g_n_embd_x4, (int)g_n_embd);
    
    /* GELU activation */
    for (mc_u32 i = 0; i < g_n_embd_x4; i++) {
        mlp_hidden[i] = gelu(mlp_hidden[i]);
    }
    
    /* Projection */
    matmul_model(out, mlp_hidden, l->mlp_proj_w, l->mlp_proj_q, l->mlp_proj_b, (int)g_n_embd, (int)g_n_embd_x4);
}

/* Forward pass for single token at position pos */
static void forward(mc_u32 token, int pos)
{
    if (g_verbose && pos == 0) {
        (void)mc_write_str(1, "DBG: forward start\n");
    }

    /* Token + position embedding */
    if (wte) {
        mc_u64 tbase = (mc_u64)token * (mc_u64)g_n_embd;
        mc_u64 pbase = (mc_u64)pos * (mc_u64)g_n_embd;
        for (mc_u32 i = 0; i < g_n_embd; i++) {
            x[i] = wte[tbase + i] + wpe[pbase + i];
        }
    } else if (g_model_qtype == GPT2_QTYPE_Q8) {
		if (!wte_q) {
			(void)mc_write_str(2, "Error: wte_q is NULL\n");
			mc_exit(1);
		}
        mc_u32 stride = 4u + g_n_embd;
        const mc_u8 *rowp0 = wte_q + (mc_u32)token * stride;
        float s = load_f32_bytes(rowp0);
        const mc_u8 *q = rowp0 + 4;
        const float *pe = wpe + (mc_u32)pos * g_n_embd;
        for (mc_u32 i = 0; i < g_n_embd; i++) {
            int qi = q8_to_i(q[i]);
            float vf = (float)qi * s;
            x[i] = vf + pe[i];
        }
    } else {
		if (!wte_q) {
			(void)mc_write_str(2, "Error: wte_q is NULL\n");
			mc_exit(1);
		}
        mc_u32 row_bytes = (mc_u32)((g_n_embd + 1) / 2);
        mc_u32 stride = 4u + row_bytes;
        const mc_u8 *rowp0 = wte_q + (mc_u32)token * stride;
        float s = load_f32_bytes(rowp0);
        const mc_u8 *rowp = rowp0 + 4;
        const float *pe = wpe + (mc_u32)pos * g_n_embd;
        for (mc_u32 i = 0; i < g_n_embd; i++) {
            mc_u8 byte = rowp[(mc_u32)i >> 1];
            mc_u8 nib = ((i & 1) == 0) ? (byte & 0xFu) : (byte >> 4);
            int qi = (nib & 0x8u) ? ((int)nib - 16) : (int)nib;
            float vf = (float)qi * s;
            x[i] = vf + pe[i];
        }
    }

    if (g_verbose && pos == 0) {
        (void)mc_write_str(1, "DBG: embed done\n");
    }
    
    /* Debug: print first embedding */
    if (g_verbose && pos == 0) {
        (void)mc_write_str(1, "After embed x[0..4]: ");
        for (int i = 0; i < 5; i++) {
            if (x[i] < 0) (void)mc_write_str(1, "-");
            mc_write_u64_dec(1, (mc_u64)(x[i] < 0 ? -x[i] * 10000 : x[i] * 10000));
            (void)mc_write_str(1, " ");
        }
        (void)mc_write_str(1, "\n");
    }
    
    /* Transformer blocks */
    for (mc_u32 layer = 0; layer < g_n_layer; layer++) {
        LayerWeights *l = &layers[layer];

        if (g_verbose && pos == 0) {
            (void)mc_write_str(1, "DBG: layer ");
            mc_write_u64_dec(1, (mc_u64)layer);
            (void)mc_write_str(1, " ln1\n");
        }
        
        /* Save residual */
        for (mc_u32 i = 0; i < g_n_embd; i++) residual[i] = x[i];
        
        /* LayerNorm 1 + Attention */
        layernorm(ln_out, x, l->ln1_g, l->ln1_b, (int)g_n_embd);

        if (g_verbose && pos == 0) {
            (void)mc_write_str(1, "DBG: layer ");
            mc_write_u64_dec(1, (mc_u64)layer);
            (void)mc_write_str(1, " attn\n");
        }
        
        /* Debug: after layernorm */
        if (g_verbose && pos == 0 && layer == 0) {
            (void)mc_write_str(1, "After LN1 ln_out[0..4]: ");
            for (int i = 0; i < 5; i++) {
                if (ln_out[i] < 0) (void)mc_write_str(1, "-");
                mc_write_u64_dec(1, (mc_u64)(ln_out[i] < 0 ? -ln_out[i] * 10000 : ln_out[i] * 10000));
                (void)mc_write_str(1, " ");
            }
            (void)mc_write_str(1, "\n");
        }
        
        attention(attn_out, (int)layer, pos);

        if (g_verbose && pos == 0) {
            (void)mc_write_str(1, "DBG: layer ");
            mc_write_u64_dec(1, (mc_u64)layer);
            (void)mc_write_str(1, " mlp\n");
        }
        
        /* Debug: after attention */
        if (g_verbose && pos == 0 && layer == 0) {
            (void)mc_write_str(1, "After attn attn_out[0..4]: ");
            for (int i = 0; i < 5; i++) {
                if (attn_out[i] < 0) (void)mc_write_str(1, "-");
                mc_write_u64_dec(1, (mc_u64)(attn_out[i] < 0 ? -attn_out[i] * 10000 : attn_out[i] * 10000));
                (void)mc_write_str(1, " ");
            }
            (void)mc_write_str(1, "\n");
        }
        
        /* Residual connection */
        for (mc_u32 i = 0; i < g_n_embd; i++) x[i] = residual[i] + attn_out[i];
        
        /* Save residual */
        for (mc_u32 i = 0; i < g_n_embd; i++) residual[i] = x[i];
        
        /* LayerNorm 2 + MLP */
        layernorm(ln_out, x, l->ln2_g, l->ln2_b, (int)g_n_embd);
        mlp(mlp_out, ln_out, (int)layer);
        
        /* Residual connection */
        for (mc_u32 i = 0; i < g_n_embd; i++) x[i] = residual[i] + mlp_out[i];
    }
    
    /* Final layer norm */
    layernorm(x, x, ln_f_g, ln_f_b, (int)g_n_embd);
}

/* Compute logits (output projection using wte^T) */
static void compute_logits(void)
{
    if (wte) {
        for (int i = 0; i < N_VOCAB; i++) {
            float sum = 0.0f;
            mc_u64 base = (mc_u64)i * (mc_u64)g_n_embd;
            for (mc_u32 j = 0; j < g_n_embd; j++) {
                sum += x[j] * wte[base + j];
            }
            logits[i] = sum;
        }
        return;
    }

    if (g_model_qtype == GPT2_QTYPE_Q8) {
        mc_u32 stride = 4u + g_n_embd;
        for (int i = 0; i < N_VOCAB; i++) {
            const mc_u8 *rowp0 = wte_q + (mc_u32)i * stride;
            float s = load_f32_bytes(rowp0);
            const mc_u8 *q = rowp0 + 4;
            float dot = 0.0f;
            for (mc_u32 j = 0; j < g_n_embd; j++) {
                dot += (float)q8_to_i(q[j]) * x[j];
            }
            logits[i] = s * dot;
        }
        return;
    }

    {
        mc_u32 row_bytes = (mc_u32)((g_n_embd + 1) / 2);
        mc_u32 stride = 4u + row_bytes;
        for (int i = 0; i < N_VOCAB; i++) {
            const mc_u8 *rowp0 = wte_q + (mc_u32)i * stride;
            float s = load_f32_bytes(rowp0);
            const mc_u8 *rowp = rowp0 + 4;
            float dot = 0.0f;
            for (mc_u32 j = 0; j < g_n_embd; j++) {
                mc_u8 byte = rowp[(mc_u32)j >> 1];
                mc_u8 nib = ((j & 1) == 0) ? (byte & 0xFu) : (byte >> 4);
                int qi = (nib & 0x8u) ? ((int)nib - 16) : (int)nib;
                dot += (float)qi * x[j];
            }
            logits[i] = s * dot;
        }
    }
}

/* Sample from logits using temperature and top-k */
static mc_u32 sample(float temperature)
{
    /* Apply temperature */
    if (temperature > 0.0f) {
        float inv_temp = 1.0f / temperature;
        for (int i = 0; i < N_VOCAB; i++) {
            logits[i] *= inv_temp;
        }
    }
    
    /* For now, use greedy sampling (argmax) */
    int best = 0;
    int second = 0;
    float best_val = logits[0];
    float second_val = logits[0];
    for (int i = 1; i < N_VOCAB; i++) {
        float v = logits[i];
        if (v > best_val) {
            second = best;
            second_val = best_val;
            best_val = v;
            best = i;
        } else if (v > second_val) {
            second_val = v;
            second = i;
        }
    }

    static int dbg = 0;
    if (g_verbose && dbg < 3) {
        mc_u32 bb;
        mc_u32 sb;
        {
            const mc_u8 *s = (const mc_u8 *)&best_val;
            mc_u8 *d = (mc_u8 *)&bb;
            d[0] = s[0];
            d[1] = s[1];
            d[2] = s[2];
            d[3] = s[3];
        }
        {
            const mc_u8 *s = (const mc_u8 *)&second_val;
            mc_u8 *d = (mc_u8 *)&sb;
            d[0] = s[0];
            d[1] = s[1];
            d[2] = s[2];
            d[3] = s[3];
        }
        mc_u32 bb_exp = (bb >> 23) & 0xFFu;
        mc_u32 sb_exp = (sb >> 23) & 0xFFu;
        mc_u32 bb_man = bb & 0x7FFFFFu;
        mc_u32 sb_man = sb & 0x7FFFFFu;
        int best_nan = (bb_exp == 0xFFu) && (bb_man != 0);
        int second_nan = (sb_exp == 0xFFu) && (sb_man != 0);

        (void)mc_write_str(1, "sample dbg best=");
        mc_write_u64_dec(1, (mc_u64)best);
        (void)mc_write_str(1, " second=");
        mc_write_u64_dec(1, (mc_u64)second);
        (void)mc_write_str(1, " best_x1e4=");
        mc_write_i64_dec(1, (mc_i64)(best_val * 10000.0f));
        (void)mc_write_str(1, " second_x1e4=");
        mc_write_i64_dec(1, (mc_i64)(second_val * 10000.0f));
        (void)mc_write_str(1, " best_nan=");
        mc_write_u64_dec(1, (mc_u64)best_nan);
        (void)mc_write_str(1, " second_nan=");
        mc_write_u64_dec(1, (mc_u64)second_nan);
        (void)mc_write_str(1, "\n");
        dbg++;
    }
    
    return (mc_u32)best;
}

static mc_u32 sample_with_params(void)
{
    /* Greedy mode */
    if (g_temperature <= 0.0f) {
        return sample(0.0f);
    }

    rng_seed_if_needed();

    int k = g_top_k;
    if (k < 0) k = 0;
    if (k > N_VOCAB) k = N_VOCAB;

    float top_p = g_top_p;
    if (top_p < 0.0f) top_p = 0.0f;
    if (top_p > 1.0f) top_p = 1.0f;

    /* Candidate set: either all vocab, or top-k, or a bounded candidate set for top-p.
       We cap to CAND_CAP for nucleus sampling to keep runtime reasonable without malloc. */
    static mc_u32 cand_idx[CAND_CAP];
    static float cand_val[CAND_CAP];
    static mc_u32 cand_order[CAND_CAP];

    mc_u32 cand_n;
    if (k == 0 && top_p == 0.0f) {
        cand_n = N_VOCAB;
    } else {
        int kk = k;
        if (kk == 0) {
            kk = CAND_CAP;
        }
        if (kk > CAND_CAP) kk = CAND_CAP;

        /* init with first k */
        for (int i = 0; i < kk; i++) {
            cand_idx[i] = (mc_u32)i;
            cand_val[i] = logits[i];
        }
        /* find current min */
        for (int i = kk; i < N_VOCAB; i++) {
            float v = logits[i];
            int min_j = 0;
            float min_v = cand_val[0];
            for (int j = 1; j < kk; j++) {
                if (cand_val[j] < min_v) { min_v = cand_val[j]; min_j = j; }
            }
            if (v > min_v) {
                cand_val[min_j] = v;
                cand_idx[min_j] = (mc_u32)i;
            }
        }
        cand_n = (mc_u32)kk;
    }

    float inv_temp = 1.0f / g_temperature;
    float maxv;
    if (cand_n == (mc_u32)N_VOCAB) {
        maxv = logits[0] * inv_temp;
        for (int i = 1; i < N_VOCAB; i++) {
            float v = logits[i] * inv_temp;
            if (v > maxv) maxv = v;
        }
    } else {
        maxv = cand_val[0] * inv_temp;
        for (mc_u32 i = 1; i < cand_n; i++) {
            float v = cand_val[i] * inv_temp;
            if (v > maxv) maxv = v;
        }
    }

    float sum = 0.0f;
    if (cand_n == (mc_u32)N_VOCAB) {
        for (int i = 0; i < N_VOCAB; i++) {
            float w = mc_expf((logits[i] * inv_temp) - maxv);
            logits[i] = w;
            sum += w;
        }
        /* Full-vocab sampling (no top-p/top-k). */
        float r = rng_f01() * sum;
        float acc = 0.0f;
        for (int i = 0; i < N_VOCAB; i++) {
            acc += logits[i];
            if (acc >= r) return (mc_u32)i;
        }
        return (mc_u32)(N_VOCAB - 1);
    }

    /* Candidate sampling: compute weights into cand_val[] */
    for (mc_u32 i = 0; i < cand_n; i++) {
        float w = mc_expf((cand_val[i] * inv_temp) - maxv);
        cand_val[i] = w;
        sum += w;
        cand_order[i] = i;
    }

    /* Optional nucleus sampling: sort candidates by weight desc, then keep smallest
       prefix whose cumulative prob >= top_p. */
    if (top_p > 0.0f) {
        /* Normalize weights to probabilities for cumulative thresholding */
        float inv_sum = 1.0f / sum;
        for (mc_u32 i = 0; i < cand_n; i++) {
            cand_val[i] *= inv_sum;
        }

        /* O(n^2) selection sort on indices (n<=512) */
        for (mc_u32 i = 0; i < cand_n; i++) {
            mc_u32 best = i;
            float bestv = cand_val[cand_order[i]];
            for (mc_u32 j = i + 1; j < cand_n; j++) {
                float v = cand_val[cand_order[j]];
                if (v > bestv) { bestv = v; best = j; }
            }
            mc_u32 tmp = cand_order[i];
            cand_order[i] = cand_order[best];
            cand_order[best] = tmp;
        }

        float cum = 0.0f;
        mc_u32 keep = 0;
        while (keep < cand_n) {
            cum += cand_val[cand_order[keep]];
            keep++;
            if (cum >= top_p) break;
        }
        if (keep == 0) keep = 1;

        float r = rng_f01() * cum;
        float acc = 0.0f;
        for (mc_u32 i = 0; i < keep; i++) {
            mc_u32 ci = cand_order[i];
            acc += cand_val[ci];
            if (acc >= r) return cand_idx[ci];
        }
        return cand_idx[cand_order[keep - 1]];
    }

    /* top-k-only (or bounded candidate without nucleus): sample from weights */
    float r = rng_f01() * sum;
    float acc = 0.0f;
    for (mc_u32 i = 0; i < cand_n; i++) {
        acc += cand_val[i];
        if (acc >= r) return cand_idx[i];
    }
    return cand_idx[cand_n - 1];
}

/* ========== Model Loading ========== */

static void *map_file(const char *path, mc_usize *out_size)
{
    mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY, 0);
    if (fd < 0) return MC_NULL;
    
    struct mc_stat st;
    if (mc_sys_fstat(fd, &st) < 0) {
        mc_sys_close(fd);
        return MC_NULL;
    }
    
    mc_i64 addr = mc_sys_mmap(MC_NULL, (mc_usize)st.st_size, PROT_READ, MAP_PRIVATE, (mc_i32)fd, 0);
    mc_sys_close((mc_i32)fd);
    if (addr < 0) return MC_NULL;
    *out_size = (mc_usize)st.st_size;
    return (void *)addr;
}

static void *alloc_anon_rw(mc_usize size)
{
    if (size == 0) return MC_NULL;
    mc_i64 addr = mc_sys_mmap(MC_NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr < 0) return MC_NULL;
    return (void *)addr;
}

static mc_i32 alloc_floats(float **out, mc_u64 n)
{
    if (!out || n == 0) return -1;
    mc_u64 bytes64 = n * 4u;
    if (bytes64 > (mc_u64)(~(mc_usize)0)) return -1;
    void *p = alloc_anon_rw((mc_usize)bytes64);
    if (!p) return -1;
    *out = (float *)p;
    return 0;
}

static mc_i32 alloc_bytes(void **out, mc_u64 n)
{
    if (!out || n == 0) return -1;
    if (n > (mc_u64)(~(mc_usize)0)) return -1;
    void *p = alloc_anon_rw((mc_usize)n);
    if (!p) return -1;
    *out = p;
    return 0;
}

static mc_u8 *align_ptr16(mc_u8 *p)
{
    mc_usize v = (mc_usize)p;
    v = (v + 15u) & ~(mc_usize)15u;
    return (mc_u8 *)v;
}

static mc_u32 pad16_u32(mc_u32 n)
{
    return (16u - (n & 15u)) & 15u;
}

static mc_i32 load_model(const char *path)
{
    mc_usize size;
    mc_u8 *data = (mc_u8 *)map_file(path, &size);
    if (!data) {
        (void)mc_write_str(2, "Error: cannot open model file\n");
        return -1;
    }
    
    /* Verify header */
    mc_u32 *header = (mc_u32 *)data;
    if (header[0] != 0x32545047) {  /* "GPT2" little-endian */
        (void)mc_write_str(2, "Error: invalid model file magic\n");
        return -1;
    }

    mc_u32 version = header[1];
    if (version != 2 && version != 3) {
        (void)mc_write_str(2, "Error: unsupported model file version (expected 2 or 3)\n");
        return -1;
    }

    g_model_qtype = GPT2_QTYPE_F32;
    mc_u32 wte_quant_flag = 0;
    if (version == 3) {
        /* reserved[0] lives at header[7] (64-byte header => 16 u32s) */
        mc_u32 qt = header[7];
        if (qt != GPT2_QTYPE_Q8 && qt != GPT2_QTYPE_Q4) {
            (void)mc_write_str(2, "Error: invalid quantization type in model header\n");
            return -1;
        }
        g_model_qtype = qt;

        /* reserved[1] bit0: whether wte is quantized */
        wte_quant_flag = header[8] & 1u;
    }
    
    /* header[2] = n_vocab, header[3] = n_ctx, etc. */
    mc_u32 n_vocab = header[2];
    mc_u32 n_ctx = header[3];
    mc_u32 n_embd = header[4];
    mc_u32 n_head = header[5];
    mc_u32 n_layer = header[6];

    if (n_vocab != N_VOCAB || n_ctx != N_CTX) {
        (void)mc_write_str(2, "Error: unsupported model vocab/ctx (expected GPT-2 50257/1024)\n");
        return -1;
    }
    if (n_embd == 0 || n_head == 0 || n_layer == 0) {
        (void)mc_write_str(2, "Error: invalid model dimensions\n");
        return -1;
    }
    if ((n_embd % n_head) != 0) {
        (void)mc_write_str(2, "Error: n_embd must be divisible by n_head\n");
        return -1;
    }

    g_n_embd = n_embd;
    g_n_head = n_head;
    g_n_layer = n_layer;
    g_n_embd_x2 = 2u * g_n_embd;
    g_n_embd_x3 = 3u * g_n_embd;
    g_n_embd_x4 = 4u * g_n_embd;
    g_ctx_embd = (mc_u32)N_CTX * g_n_embd;
    g_kv_cache_size = g_n_layer * g_ctx_embd;

    if (alloc_runtime_buffers() < 0) {
        (void)mc_write_str(2, "Error: failed to allocate runtime buffers\n");
        return -1;
    }

    if (!g_raw || g_verbose) {
        (void)mc_write_str(1, "Loading GPT-2 model... n_embd=");
        mc_write_u64_dec(1, (mc_u64)g_n_embd);
        (void)mc_write_str(1, " n_head=");
        mc_write_u64_dec(1, (mc_u64)g_n_head);
        (void)mc_write_str(1, " n_layer=");
        mc_write_u64_dec(1, (mc_u64)g_n_layer);
        (void)mc_write_str(1, "\n");
    }
    
    /* Set up weight pointers */
    mc_u8 *p = (mc_u8 *)(data + 64);  /* Skip 64-byte header */

    wte = 0;
    wte_q = 0;

    /* Token embeddings */
    if (g_model_qtype == GPT2_QTYPE_F32 || !wte_quant_flag) {
        wte = (float *)p;
        p += (mc_u32)N_VOCAB * g_n_embd * 4u;
    } else {
        mc_u32 row_bytes = q_row_bytes((int)g_model_qtype, (int)g_n_embd);
        mc_u32 stride = 4u + row_bytes;
        wte_q = (const mc_u8 *)p;
        mc_u32 wte_q_bytes = (mc_u32)N_VOCAB * stride;
        p += wte_q_bytes;
        /* v3 format: pad-to-16 after quantized wte so wpe (f32) is 16-byte aligned.
           If the padding is missing (older files), fail loudly instead of silently mis-parsing. */
        mc_u32 pad = pad16_u32(wte_q_bytes);
        for (mc_u32 i = 0; i < pad; i++) {
            if (p[i] != 0) {
                (void)mc_write_str(2, "Error: v3 model missing pad16 after quantized wte; regenerate model\n");
                return -1;
            }
        }
        p += pad;
    }

    /* Position embeddings (always f32) */
    wpe = (float *)p;
    p += (mc_u32)N_CTX * g_n_embd * 4u;
    
    /* Per-layer weights */
    for (mc_u32 l = 0; l < g_n_layer; l++) {
        /* Attention LayerNorm */
        layers[l].ln1_g = (float *)p; p += g_n_embd * 4u;
        layers[l].ln1_b = (float *)p; p += g_n_embd * 4u;

        /* Attention QKV */
        layers[l].attn_qkv_w = 0;
        layers[l].attn_qkv_q = 0;
        if (g_model_qtype == GPT2_QTYPE_F32) {
            layers[l].attn_qkv_w = (float *)p;
            p += g_n_embd * (mc_u32)(3u * g_n_embd) * 4u;
        } else {
            mc_u32 row_bytes = q_row_bytes((int)g_model_qtype, (int)g_n_embd);
            mc_u32 stride = 4u + row_bytes;
            layers[l].attn_qkv_q = (const mc_u8 *)p;
            p += (mc_u32)(3u * g_n_embd) * stride;
			p = align_ptr16(p);
        }
        layers[l].attn_qkv_b = (float *)p; p += (mc_u32)(3u * g_n_embd) * 4u;

        /* Attention output projection */
        layers[l].attn_proj_w = 0;
        layers[l].attn_proj_q = 0;
        if (g_model_qtype == GPT2_QTYPE_F32) {
            layers[l].attn_proj_w = (float *)p;
            p += g_n_embd * g_n_embd * 4u;
        } else {
            mc_u32 row_bytes = q_row_bytes((int)g_model_qtype, (int)g_n_embd);
            mc_u32 stride = 4u + row_bytes;
            layers[l].attn_proj_q = (const mc_u8 *)p;
			p += g_n_embd * stride;
			p = align_ptr16(p);
        }
		layers[l].attn_proj_b = (float *)p; p += g_n_embd * 4u;

        /* MLP LayerNorm */
        layers[l].ln2_g = (float *)p; p += g_n_embd * 4u;
        layers[l].ln2_b = (float *)p; p += g_n_embd * 4u;

        /* MLP FC */
        layers[l].mlp_fc_w = 0;
        layers[l].mlp_fc_q = 0;
        if (g_model_qtype == GPT2_QTYPE_F32) {
            layers[l].mlp_fc_w = (float *)p;
            p += g_n_embd * (mc_u32)(4u * g_n_embd) * 4u;
        } else {
            mc_u32 row_bytes = q_row_bytes((int)g_model_qtype, (int)g_n_embd);
            mc_u32 stride = 4u + row_bytes;
            layers[l].mlp_fc_q = (const mc_u8 *)p;
			p += (mc_u32)(4u * g_n_embd) * stride;
			p = align_ptr16(p);
        }
        layers[l].mlp_fc_b = (float *)p; p += (mc_u32)(4u * g_n_embd) * 4u;

        /* MLP projection */
        layers[l].mlp_proj_w = 0;
        layers[l].mlp_proj_q = 0;
        if (g_model_qtype == GPT2_QTYPE_F32) {
            layers[l].mlp_proj_w = (float *)p;
            p += (mc_u32)(4u * g_n_embd) * g_n_embd * 4u;
        } else {
            mc_u32 row_bytes = q_row_bytes((int)g_model_qtype, (int)(4u * g_n_embd));
            mc_u32 stride = 4u + row_bytes;
            layers[l].mlp_proj_q = (const mc_u8 *)p;
			p += g_n_embd * stride;
			p = align_ptr16(p);
        }
		layers[l].mlp_proj_b = (float *)p; p += g_n_embd * 4u;
    }

    /* Final LayerNorm */
    ln_f_g = (float *)p; p += g_n_embd * 4u;
    ln_f_b = (float *)p; p += g_n_embd * 4u;
    
    if (!g_raw || g_verbose) {
        (void)mc_write_str(1, "Model loaded successfully\n");
    }
    
    /* Debug: check wte values */
    if (g_verbose) {
        (void)mc_write_str(1, "Debug wte[0..4]: ");
        for (int i = 0; i < 5; i++) {
            float v;
            if (wte) {
                v = wte[i];
            } else if (g_model_qtype == GPT2_QTYPE_Q8) {
                const mc_u8 *rowp0 = wte_q;
                float s = load_f32_bytes(rowp0);
                const mc_u8 *q = rowp0 + 4;
                v = (float)q8_to_i(q[i]) * s;
            } else {
                const mc_u8 *rowp0 = wte_q;
                float s = load_f32_bytes(rowp0);
                const mc_u8 *rowp = rowp0 + 4;
                mc_u8 byte = rowp[(mc_u32)i >> 1];
                mc_u8 nib = ((i & 1) == 0) ? (byte & 0xFu) : (byte >> 4);
                int qi = (nib & 0x8u) ? ((int)nib - 16) : (int)nib;
                v = (float)qi * s;
            }
            if (v < 0) (void)mc_write_str(1, "-");
            mc_write_u64_dec(1, (mc_u64)(v < 0 ? -v * 10000 : v * 10000));
            (void)mc_write_str(1, " ");
        }
        (void)mc_write_str(1, "\n");
    }
    
    return 0;
}

/* ========== Main ========== */

int main(int argc, char **argv)
{
    /* Parse flags first; banner printing depends on --raw. */

    /* Pre-scan for global flags that affect early output, regardless of position. */
    for (int i = 1; i < argc; i++) {
        if (argv[i] && (mc_streq(argv[i], "--raw"))) g_raw = 1;
        if (argv[i] && (mc_streq(argv[i], "-v") || mc_streq(argv[i], "--verbose"))) g_verbose = 1;
    }

    int argi = 1;
    const char *tokenizer_dir = "117M";
    int text_mode = 0;
    int stdin_mode = 0;

    while (argi < argc && argv[argi][0] == '-') {
        if (mc_streq(argv[argi], "-v") || mc_streq(argv[argi], "--verbose")) {
            g_verbose = 1;
            argi++;
            continue;
        }
        if (mc_streq(argv[argi], "--tokenizer-dir")) {
            if (argi + 1 >= argc) {
                (void)mc_write_str(2, "Error: --tokenizer-dir needs an argument\n");
                return 1;
            }
            tokenizer_dir = argv[argi + 1];
            argi += 2;
            continue;
        }
        if (mc_streq(argv[argi], "--text") || mc_streq(argv[argi], "-t")) {
            text_mode = 1;
            argi++;
            continue;
        }
        if (mc_streq(argv[argi], "--stdin")) {
            text_mode = 1;
            stdin_mode = 1;
            argi++;
            continue;
        }
        if (mc_streq(argv[argi], "--raw")) {
            g_raw = 1;
            argi++;
            continue;
        }
        if (mc_streq(argv[argi], "--max-tokens")) {
            if (argi + 1 >= argc) {
                (void)mc_write_str(2, "Error: --max-tokens needs an integer\n");
                return 1;
            }
            mc_i32 v;
            if (mc_parse_i32_dec(argv[argi + 1], &v) != 0 || v < 0) {
                (void)mc_write_str(2, "Error: invalid --max-tokens\n");
                return 1;
            }
            g_max_gen_tokens = v;
            argi += 2;
            continue;
        }
        if (mc_streq(argv[argi], "--top-k")) {
            if (argi + 1 >= argc) {
                (void)mc_write_str(2, "Error: --top-k needs an integer\n");
                return 1;
            }
            mc_i32 v;
            if (mc_parse_i32_dec(argv[argi + 1], &v) != 0 || v < 0) {
                (void)mc_write_str(2, "Error: invalid --top-k\n");
                return 1;
            }
            g_top_k = v;
            argi += 2;
            continue;
        }
        if (mc_streq(argv[argi], "--temperature")) {
            if (argi + 1 >= argc) {
                (void)mc_write_str(2, "Error: --temperature needs a number\n");
                return 1;
            }
            float t;
            if (parse_float_simple(argv[argi + 1], &t) != 0) {
                (void)mc_write_str(2, "Error: invalid --temperature\n");
                return 1;
            }
            g_temperature = t;
            argi += 2;
            continue;
        }
        if (mc_streq(argv[argi], "--top-p")) {
            if (argi + 1 >= argc) {
                (void)mc_write_str(2, "Error: --top-p needs a number\n");
                return 1;
            }
            float p;
            if (parse_float_simple(argv[argi + 1], &p) != 0) {
                (void)mc_write_str(2, "Error: invalid --top-p\n");
                return 1;
            }
            g_top_p = p;
            argi += 2;
            continue;
        }
        if (mc_streq(argv[argi], "--seed")) {
            if (argi + 1 >= argc) {
                (void)mc_write_str(2, "Error: --seed needs an integer\n");
                return 1;
            }
            mc_u64 s;
            if (mc_parse_u64_dec(argv[argi + 1], &s) != 0) {
                (void)mc_write_str(2, "Error: invalid --seed\n");
                return 1;
            }
            g_rng_state = (mc_u32)(s ? s : 1);
            g_rng_seeded = 1;
            argi += 2;
            continue;
        }
        if (mc_streq(argv[argi], "-h") || mc_streq(argv[argi], "--help")) {
            (void)mc_write_str(1, "Usage:\n");
            (void)mc_write_str(1, "  gpt2 [-v|--verbose] [--tokenizer-dir DIR] <model_path> <token_ids...>\n");
            (void)mc_write_str(1, "  gpt2 [-v|--verbose] [--tokenizer-dir DIR] <model_path> --text <prompt...>\n");
            (void)mc_write_str(1, "  gpt2 [-v|--verbose] [--tokenizer-dir DIR] <model_path> --stdin\n");
            (void)mc_write_str(1, "\nGeneration options:\n");
            (void)mc_write_str(1, "  --raw                 Print only generated text (no banner/labels)\n");
            (void)mc_write_str(1, "  --max-tokens N         Generate up to N tokens (default 20)\n");
            (void)mc_write_str(1, "  --temperature T        Sampling temperature (default 1.0; use 0 for greedy)\n");
            (void)mc_write_str(1, "  --top-k K              Sample from top K tokens (default 40; 0 = full vocab)\n");
            (void)mc_write_str(1, "  --top-p P              Nucleus sampling threshold in (0,1] (default 0=off)\n");
            (void)mc_write_str(1, "  --seed S               RNG seed (optional; otherwise uses getrandom)\n");
            (void)mc_write_str(1, "\nExamples:\n");
            (void)mc_write_str(1, "  gpt2 gpt2_v2.bin 15496 11 995 0\n");
            (void)mc_write_str(1, "  gpt2 --tokenizer-dir 117M gpt2_v2.bin --text Hello world\n");
            (void)mc_write_str(1, "  gpt2 --raw --temperature 0.8 --top-k 40 gpt2_v2.bin --text Hello\n");
            return 0;
        }
        break;
    }

    if (!g_raw || g_verbose) {
        (void)mc_write_str(1, "GPT-2 Inference Engine\n");
        (void)mc_write_str(1, "======================\n\n");
    }

    if (argc - argi < 1) {
        (void)mc_write_str(2, "Usage: gpt2 [-v|--verbose] [--tokenizer-dir DIR] <model_path> <token_ids...>\n");
        (void)mc_write_str(2, "   or: gpt2 [-v|--verbose] [--tokenizer-dir DIR] <model_path> --text <prompt...>\n");
        (void)mc_write_str(2, "   or: gpt2 [-v|--verbose] [--tokenizer-dir DIR] <model_path> --stdin\n");
        return 1;
    }

    const char *model_path = argv[argi++];

    /* Allow tokenizer/text flags after the model path as well. */
    while (argi < argc && argv[argi][0] == '-') {
        if (mc_streq(argv[argi], "--tokenizer-dir")) {
            if (argi + 1 >= argc) {
                (void)mc_write_str(2, "Error: --tokenizer-dir needs an argument\n");
                return 1;
            }
            tokenizer_dir = argv[argi + 1];
            argi += 2;
            continue;
        }
        if (mc_streq(argv[argi], "--text") || mc_streq(argv[argi], "-t")) {
            text_mode = 1;
            argi++;
            continue;
        }
        if (mc_streq(argv[argi], "--stdin")) {
            text_mode = 1;
            stdin_mode = 1;
            argi++;
            continue;
        }
        if (mc_streq(argv[argi], "-v") || mc_streq(argv[argi], "--verbose")) {
            g_verbose = 1;
            argi++;
            continue;
        }
        if (mc_streq(argv[argi], "--raw")) {
            g_raw = 1;
            argi++;
            continue;
        }
        if (mc_streq(argv[argi], "--max-tokens")) {
            if (argi + 1 >= argc) {
                (void)mc_write_str(2, "Error: --max-tokens needs an integer\n");
                return 1;
            }
            mc_i32 v;
            if (mc_parse_i32_dec(argv[argi + 1], &v) != 0 || v < 0) {
                (void)mc_write_str(2, "Error: invalid --max-tokens\n");
                return 1;
            }
            g_max_gen_tokens = v;
            argi += 2;
            continue;
        }
        if (mc_streq(argv[argi], "--top-k")) {
            if (argi + 1 >= argc) {
                (void)mc_write_str(2, "Error: --top-k needs an integer\n");
                return 1;
            }
            mc_i32 v;
            if (mc_parse_i32_dec(argv[argi + 1], &v) != 0 || v < 0) {
                (void)mc_write_str(2, "Error: invalid --top-k\n");
                return 1;
            }
            g_top_k = v;
            argi += 2;
            continue;
        }
        if (mc_streq(argv[argi], "--temperature")) {
            if (argi + 1 >= argc) {
                (void)mc_write_str(2, "Error: --temperature needs a number\n");
                return 1;
            }
            float t;
            if (parse_float_simple(argv[argi + 1], &t) != 0) {
                (void)mc_write_str(2, "Error: invalid --temperature\n");
                return 1;
            }
            g_temperature = t;
            argi += 2;
            continue;
        }
        if (mc_streq(argv[argi], "--top-p")) {
            if (argi + 1 >= argc) {
                (void)mc_write_str(2, "Error: --top-p needs a number\n");
                return 1;
            }
            float p;
            if (parse_float_simple(argv[argi + 1], &p) != 0) {
                (void)mc_write_str(2, "Error: invalid --top-p\n");
                return 1;
            }
            g_top_p = p;
            argi += 2;
            continue;
        }
        if (mc_streq(argv[argi], "--seed")) {
            if (argi + 1 >= argc) {
                (void)mc_write_str(2, "Error: --seed needs an integer\n");
                return 1;
            }
            mc_u64 s;
            if (mc_parse_u64_dec(argv[argi + 1], &s) != 0) {
                (void)mc_write_str(2, "Error: invalid --seed\n");
                return 1;
            }
            g_rng_state = (mc_u32)(s ? s : 1);
            g_rng_seeded = 1;
            argi += 2;
            continue;
        }
        if (mc_streq(argv[argi], "-h") || mc_streq(argv[argi], "--help")) {
            (void)mc_write_str(1, "Usage:\n");
            (void)mc_write_str(1, "  gpt2 [-v|--verbose] [--tokenizer-dir DIR] <model_path> <token_ids...>\n");
            (void)mc_write_str(1, "  gpt2 [-v|--verbose] [--tokenizer-dir DIR] <model_path> --text <prompt...>\n");
            (void)mc_write_str(1, "  gpt2 [-v|--verbose] [--tokenizer-dir DIR] <model_path> --stdin\n");
            return 0;
        }
        break;
    }

    /* (banner is handled above) */

    /* Load model */
    if (load_model(model_path) < 0) {
        return 1;
    }

    mc_u32 input_ids[MAX_PROMPT_TOKENS];
    int n_input = 0;

    /* Text mode can be specified via --text / --stdin after the model path as well. */
    if (!text_mode && argi < argc && (mc_streq(argv[argi], "--text") || mc_streq(argv[argi], "-t"))) {
        text_mode = 1;
        argi++;
    }
    if (!text_mode && argi < argc && mc_streq(argv[argi], "--stdin")) {
        text_mode = 1;
        stdin_mode = 1;
        argi++;
    }

    if (text_mode) {
        if (tokenizer_init_from_dir(tokenizer_dir) < 0) return 1;

        static mc_u8 prompt_bytes[4096];
        mc_u32 prompt_len = 0;

        if (stdin_mode) {
            /* Read up to 4096 bytes from stdin. */
            mc_i64 r = mc_sys_read(0, prompt_bytes, sizeof(prompt_bytes));
            if (r < 0) {
                (void)mc_write_str(2, "Error: failed to read stdin\n");
                return 1;
            }
            prompt_len = (mc_u32)r;
            while (prompt_len > 0 && (prompt_bytes[prompt_len - 1] == '\n' || prompt_bytes[prompt_len - 1] == '\r')) {
                prompt_len--;
            }
        } else {
            /* Join remaining args with spaces. */
            for (int i = argi; i < argc && prompt_len + 1 < sizeof(prompt_bytes); i++) {
                if (i > argi) prompt_bytes[prompt_len++] = ' ';
                const char *s = argv[i];
                while (*s && prompt_len + 1 < sizeof(prompt_bytes)) {
                    prompt_bytes[prompt_len++] = (mc_u8)*s++;
                }
            }
        }

        n_input = (int)encode_text_to_ids(prompt_bytes, prompt_len, input_ids, MAX_PROMPT_TOKENS);
        if (n_input <= 0) {
            (void)mc_write_str(2, "Error: prompt produced no tokens\n");
            return 1;
        }

        if (g_verbose && (!g_raw || g_verbose)) {
            (void)mc_write_str(1, "\nPrompt tokens: ");
            mc_write_u64_dec(1, (mc_u64)n_input);
            (void)mc_write_str(1, "\n");
        }
    } else {
        if (argc - argi < 1) {
            (void)mc_write_str(2, "Error: expected token IDs or --text/--stdin\n");
            return 1;
        }

        /* Parse input token IDs */
        for (int i = argi; i < argc && n_input < MAX_PROMPT_TOKENS; i++) {
            const char *s = argv[i];
            if (!s || !*s) {
                (void)mc_write_str(2, "Error: empty token id\n");
                return 1;
            }
            mc_u32 id = 0;
            for (const char *p = s; *p; p++) {
                if (*p < '0' || *p > '9') {
                    (void)mc_write_str(2, "Error: non-numeric token id: ");
                    (void)mc_write_str(2, s);
                    (void)mc_write_str(2, "\n");
                    return 1;
                }
                id = id * 10 + (mc_u32)(*p - '0');
            }
            input_ids[n_input++] = id;
        }

        if (!g_raw || g_verbose) {
            (void)mc_write_str(1, "\nInput tokens: ");
            mc_write_u64_dec(1, (mc_u64)n_input);
            (void)mc_write_str(1, "\n");
        }
    }
    
    /* Process input tokens */
    for (int pos = 0; pos < n_input; pos++) {
        if (g_verbose) {
            (void)mc_write_str(1, "Processing position ");
            mc_write_u64_dec(1, pos);
            (void)mc_write_str(1, " (token ");
            mc_write_u64_dec(1, input_ids[pos]);
            (void)mc_write_str(1, ")\n");
        }
        
        forward(input_ids[pos], pos);
    }
    
    /* Generate new tokens */
    if (!g_raw) {
        (void)mc_write_str(1, "\nGenerating...\n");
    }
    
    /* Debug: print x[0..4] */
    if (g_verbose) {
        (void)mc_write_str(1, "Debug x[0..4]: ");
        for (int i = 0; i < 5; i++) {
            if (x[i] < 0) (void)mc_write_str(1, "-");
            mc_write_u64_dec(1, (mc_u64)(x[i] < 0 ? -x[i] * 10000 : x[i] * 10000));
            (void)mc_write_str(1, " ");
        }
        (void)mc_write_str(1, "\n");
    }
    
    int gen_tokens = g_max_gen_tokens;
    if (gen_tokens > MAX_GEN_TOKENS) gen_tokens = MAX_GEN_TOKENS;
    mc_u32 generated[MAX_GEN_TOKENS];
    int n_generated = 0;
    
    for (int i = 0; i < gen_tokens; i++) {
        compute_logits();
        mc_u32 next_token = sample_with_params();
        
        /* Stop on end of text */
        if (next_token == 50256) break;  /* <|endoftext|> */
        
        generated[n_generated++] = next_token;

        if (text_mode) {
            /* Stream decoded bytes for this token */
            mc_u8 buf[1024];
            mc_u32 blen = decode_id_to_bytes(next_token, buf, sizeof(buf));
            if (blen > 0) (void)mc_write_all(1, buf, blen);
        } else {
            (void)mc_write_str(1, "Generated token: ");
            mc_write_u64_dec(1, next_token);
            (void)mc_write_str(1, "\n");
        }
        
        /* Feed generated token back */
        int pos = n_input + i;
        forward(next_token, pos);
    }
    
    if (text_mode) {
        (void)mc_write_str(1, "\n");
        if (g_verbose) {
            (void)mc_write_str(1, "\nGenerated ");
            mc_write_u64_dec(1, (mc_u64)n_generated);
            (void)mc_write_str(1, " tokens\n");
        }
    } else {
        (void)mc_write_str(1, "\nGenerated ");
        mc_write_u64_dec(1, (mc_u64)n_generated);
        (void)mc_write_str(1, " tokens\n");

        (void)mc_write_str(1, "Token IDs: ");
        for (int i = 0; i < n_generated; i++) {
            mc_write_u64_dec(1, generated[i]);
            (void)mc_write_str(1, " ");
        }
        (void)mc_write_str(1, "\n");
    }
    
    return 0;
}
