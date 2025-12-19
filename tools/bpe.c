/* BPE Tokenizer for GPT-2 - No libc, only syscalls */
#include "mc.h"

/* GPT-2 uses byte-level BPE with 50257 vocab tokens and 50000 merges */
#define MAX_VOCAB     50257
#define MAX_MERGES    50000
#define MAX_TOKEN_LEN 256
#define MAX_TEXT_LEN  65536

/* mmap constants */
#define PROT_READ   1
#define MAP_PRIVATE 2

/* Token entry: maps byte string to ID */
typedef struct {
    mc_u8   bytes[MAX_TOKEN_LEN];
    mc_u32  len;
    mc_u32  id;
} Token;

/* Merge rule: pair of tokens to merge */
typedef struct {
    mc_u8   first[MAX_TOKEN_LEN];
    mc_u32  first_len;
    mc_u8   second[MAX_TOKEN_LEN];
    mc_u32  second_len;
    mc_u32  rank;  /* lower = higher priority */
} Merge;

/* Global tokenizer state */
static Token  vocab[MAX_VOCAB];
static mc_u32 vocab_count;
static Merge  merges[MAX_MERGES];
static mc_u32 merge_count;

/* Byte encoder table: GPT-2 maps bytes 0-255 to printable chars */
/* Bytes 33-126, 161-172, 174-255 map to themselves (offset by index) */
/* Others (0-32, 127-160, 173) map to 256+ */
static mc_u16 byte_encoder[256];
static mc_u8  byte_decoder[512];  /* inverse mapping */

/* Helper: map file into memory */
static void *map_file(const char *path, mc_usize *out_size)
{
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

static void init_byte_encoder(void)
{
    mc_u32 n = 0;
    mc_u32 i;
    
    /* Printable ASCII: ! to ~ */
    for (i = 33; i <= 126; i++) {
        byte_encoder[i] = (mc_u16)i;
        byte_decoder[i] = (mc_u8)i;
        n++;
    }
    /* Latin-1 supplement printable: onwards */
    for (i = 161; i <= 172; i++) {
        byte_encoder[i] = (mc_u16)i;
        byte_decoder[i] = (mc_u8)i;
        n++;
    }
    for (i = 174; i <= 255; i++) {
        byte_encoder[i] = (mc_u16)i;
        byte_decoder[i] = (mc_u8)i;
        n++;
    }
    /* Map remaining bytes to 256+ in order */
    mc_u32 next = 256;
    for (i = 0; i < 256; i++) {
        if (byte_encoder[i] == 0) {
            /* Not yet assigned - includes byte 0 */
            byte_encoder[i] = (mc_u16)next;
            byte_decoder[next] = (mc_u8)i;
            next++;
        }
    }
}

/* Decode a JSON string escape sequence */
/* Returns number of bytes consumed from input, writes result to out */
static mc_u32 decode_json_escape(const mc_u8 *s, mc_u8 *out, mc_u32 *out_len)
{
    if (s[0] != '\\') {
        out[*out_len] = s[0];
        (*out_len)++;
        return 1;
    }
    
    /* Escape sequence */
    switch (s[1]) {
    case '"':  out[*out_len] = '"';  (*out_len)++; return 2;
    case '\\': out[*out_len] = '\\'; (*out_len)++; return 2;
    case '/':  out[*out_len] = '/';  (*out_len)++; return 2;
    case 'b':  out[*out_len] = '\b'; (*out_len)++; return 2;
    case 'f':  out[*out_len] = '\f'; (*out_len)++; return 2;
    case 'n':  out[*out_len] = '\n'; (*out_len)++; return 2;
    case 'r':  out[*out_len] = '\r'; (*out_len)++; return 2;
    case 't':  out[*out_len] = '\t'; (*out_len)++; return 2;
    case 'u': {
        /* Unicode escape \uXXXX */
        mc_u32 cp = 0;
        for (mc_u32 i = 0; i < 4; i++) {
            mc_u8 c = s[2 + i];
            mc_u32 v;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = 10 + c - 'a';
            else if (c >= 'A' && c <= 'F') v = 10 + c - 'A';
            else return 0;  /* Invalid */
            cp = (cp << 4) | v;
        }
        
        /* Encode the codepoint as UTF-8 - tokens are UTF-8 strings */
        if (cp < 0x80) {
            out[*out_len] = (mc_u8)cp;
            (*out_len)++;
        } else if (cp < 0x800) {
            out[*out_len] = (mc_u8)(0xC0 | (cp >> 6));
            (*out_len)++;
            out[*out_len] = (mc_u8)(0x80 | (cp & 0x3F));
            (*out_len)++;
        } else {
            out[*out_len] = (mc_u8)(0xE0 | (cp >> 12));
            (*out_len)++;
            out[*out_len] = (mc_u8)(0x80 | ((cp >> 6) & 0x3F));
            (*out_len)++;
            out[*out_len] = (mc_u8)(0x80 | (cp & 0x3F));
            (*out_len)++;
        }
        return 6;
    }
    default:
        out[*out_len] = s[1];
        (*out_len)++;
        return 2;
    }
}

/* Parse encoder.json: {"token": id, ...} */
static mc_i32 load_encoder(const char *path)
{
    mc_usize size;
    mc_u8 *data = (mc_u8 *)map_file(path, &size);
    if (!data) {
        (void)mc_write_str(2, "Error: cannot open encoder.json\n");
        return -1;
    }
    
    vocab_count = 0;
    mc_u64 pos = 0;
    
    /* Skip to first { */
    while (pos < (mc_u64)size && data[pos] != '{') pos++;
    pos++;  /* skip { */
    
    while (pos < (mc_u64)size && vocab_count < MAX_VOCAB) {
        /* Skip whitespace */
        while (pos < (mc_u64)size && (data[pos] == ' ' || data[pos] == '\n' || 
               data[pos] == '\r' || data[pos] == '\t' || data[pos] == ',')) {
            pos++;
        }
        
        if (pos >= (mc_u64)size || data[pos] == '}') break;
        
        /* Parse "token": id */
        if (data[pos] != '"') {
            (void)mc_write_str(2, "Error: expected \" in encoder.json\n");
            break;
        }
        pos++;  /* skip opening " */
        
        /* Parse token string */
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
        pos++;  /* skip closing " */
        
        /* Skip : */
        while (pos < (mc_u64)size && data[pos] != ':') pos++;
        pos++;
        
        /* Parse ID */
        while (pos < (mc_u64)size && data[pos] == ' ') pos++;
        
        mc_u32 id = 0;
        while (pos < (mc_u64)size && data[pos] >= '0' && data[pos] <= '9') {
            id = id * 10 + (data[pos] - '0');
            pos++;
        }
        t->id = id;
        
        vocab_count++;
    }
    
    mc_sys_munmap(data, (mc_usize)size);
    
    (void)mc_write_str(1, "Loaded ");
    mc_write_u64_dec(1, vocab_count);
    (void)mc_write_str(1, " tokens from encoder.json\n");
    
    return 0;
}

/* Parse vocab.bpe: merge rules, one per line */
static mc_i32 load_merges(const char *path)
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
        /* Skip to start of line */
        mc_u64 line_start = pos;
        
        /* Find end of line */
        while (pos < (mc_u64)size && data[pos] != '\n') pos++;
        mc_u64 line_end = pos;
        if (pos < (mc_u64)size) pos++;  /* skip newline */
        
        line++;
        
        /* Skip first line (version header) */
        if (line == 1) continue;
        
        /* Skip empty lines */
        if (line_end == line_start) continue;
        
        /* Parse: "first second" (space-separated) */
        Merge *m = &merges[merge_count];
        m->first_len = 0;
        m->second_len = 0;
        m->rank = merge_count;
        
        mc_u64 p = line_start;
        
        /* Parse first token (until space) */
        while (p < line_end && data[p] != ' ') {
            m->first[m->first_len++] = data[p];
            p++;
        }
        
        /* Skip space */
        if (p < line_end && data[p] == ' ') p++;
        
        /* Parse second token (until end of line) */
        while (p < line_end) {
            m->second[m->second_len++] = data[p];
            p++;
        }
        
        if (m->first_len > 0 && m->second_len > 0) {
            merge_count++;
        }
    }
    
    mc_sys_munmap(data, (mc_usize)size);
    
    (void)mc_write_str(1, "Loaded ");
    mc_write_u64_dec(1, merge_count);
    (void)mc_write_str(1, " merges from vocab.bpe\n");
    
    return 0;
}

/* Find token ID by bytes */
static mc_i32 find_token_id(const mc_u8 *bytes, mc_u32 len)
{
    for (mc_u32 i = 0; i < vocab_count; i++) {
        if (vocab[i].len == len) {
            mc_u32 match = 1;
            for (mc_u32 j = 0; j < len; j++) {
                if (vocab[i].bytes[j] != bytes[j]) {
                    match = 0;
                    break;
                }
            }
            if (match) return (mc_i32)vocab[i].id;
        }
    }
    return -1;
}

/* Find token bytes by ID */
static Token *find_token_by_id(mc_u32 id)
{
    for (mc_u32 i = 0; i < vocab_count; i++) {
        if (vocab[i].id == id) return &vocab[i];
    }
    return 0;
}

/* BPE encoding: a sequence of byte tokens that we merge */
typedef struct {
    mc_u8  bytes[MAX_TOKEN_LEN];
    mc_u32 len;
} BPEToken;

typedef struct {
    BPEToken tokens[MAX_TEXT_LEN];
    mc_u32   count;
} BPESequence;

/* Convert input text to GPT-2's byte representation */
static void text_to_bpe_bytes(const mc_u8 *text, mc_u32 text_len, BPESequence *seq)
{
    seq->count = 0;
    
    for (mc_u32 i = 0; i < text_len && seq->count < MAX_TEXT_LEN; i++) {
        mc_u8 b = text[i];
        mc_u16 cp = byte_encoder[b];
        
        BPEToken *t = &seq->tokens[seq->count];
        t->len = 0;
        
        /* Encode codepoint as UTF-8 */
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

/* Find best merge pair in sequence */
static mc_i32 find_best_merge(BPESequence *seq, mc_u32 *best_i)
{
    mc_i32 best_rank = -1;
    
    for (mc_u32 i = 0; i + 1 < seq->count; i++) {
        BPEToken *a = &seq->tokens[i];
        BPEToken *b = &seq->tokens[i + 1];
        
        /* Look for this pair in merges */
        for (mc_u32 m = 0; m < merge_count; m++) {
            Merge *merge = &merges[m];
            
            if (a->len == merge->first_len && b->len == merge->second_len) {
                mc_u32 match = 1;
                for (mc_u32 j = 0; j < a->len && match; j++) {
                    if (a->bytes[j] != merge->first[j]) match = 0;
                }
                for (mc_u32 j = 0; j < b->len && match; j++) {
                    if (b->bytes[j] != merge->second[j]) match = 0;
                }
                
                if (match) {
                    if (best_rank < 0 || (mc_i32)merge->rank < best_rank) {
                        best_rank = (mc_i32)merge->rank;
                        *best_i = i;
                    }
                    break;  /* Found merge for this pair, continue to next pair */
                }
            }
        }
    }
    
    return best_rank;
}

/* Apply merge at position i */
static void apply_merge(BPESequence *seq, mc_u32 i)
{
    if (i + 1 >= seq->count) return;
    
    BPEToken *a = &seq->tokens[i];
    BPEToken *b = &seq->tokens[i + 1];
    
    /* Merge b into a */
    for (mc_u32 j = 0; j < b->len && a->len < MAX_TOKEN_LEN; j++) {
        a->bytes[a->len++] = b->bytes[j];
    }
    
    /* Remove token at i+1 */
    for (mc_u32 j = i + 1; j + 1 < seq->count; j++) {
        seq->tokens[j] = seq->tokens[j + 1];
    }
    seq->count--;
}

/* Encode text to token IDs */
static mc_u32 encode(const mc_u8 *text, mc_u32 text_len, mc_u32 *output_ids, mc_u32 max_output)
{
    static BPESequence seq;  /* Static to avoid stack overflow */
    
    /* Convert to BPE byte sequence */
    text_to_bpe_bytes(text, text_len, &seq);
    
    /* Apply BPE merges until no more possible */
    while (1) {
        mc_u32 best_i;
        mc_i32 best_rank = find_best_merge(&seq, &best_i);
        if (best_rank < 0) break;
        apply_merge(&seq, best_i);
    }
    
    /* Convert tokens to IDs */
    mc_u32 output_count = 0;
    for (mc_u32 i = 0; i < seq.count && output_count < max_output; i++) {
        BPEToken *t = &seq.tokens[i];
        mc_i32 id = find_token_id(t->bytes, t->len);
        if (id >= 0) {
            output_ids[output_count++] = (mc_u32)id;
        } else {
            (void)mc_write_str(2, "Warning: unknown token\n");
        }
    }
    
    return output_count;
}

/* Decode token IDs to text */
static mc_u32 decode(const mc_u32 *ids, mc_u32 id_count, mc_u8 *output, mc_u32 max_output)
{
    mc_u32 output_len = 0;
    
    for (mc_u32 i = 0; i < id_count; i++) {
        Token *t = find_token_by_id(ids[i]);
        if (!t) continue;
        
        /* Token bytes are in GPT-2 encoding, need to decode */
        for (mc_u32 j = 0; j < t->len && output_len < max_output; j++) {
            mc_u8 b = t->bytes[j];
            
            /* Check if it's a UTF-8 sequence (for Ġ etc) */
            if (b >= 0xC0 && j + 1 < t->len) {
                /* Decode UTF-8 to codepoint */
                mc_u32 cp;
                mc_u32 consumed = 1;
                
                if ((b & 0xE0) == 0xC0 && j + 1 < t->len) {
                    cp = ((b & 0x1F) << 6) | (t->bytes[j + 1] & 0x3F);
                    consumed = 2;
                } else if ((b & 0xF0) == 0xE0 && j + 2 < t->len) {
                    cp = ((b & 0x0F) << 12) | ((t->bytes[j + 1] & 0x3F) << 6) | 
                         (t->bytes[j + 2] & 0x3F);
                    consumed = 3;
                } else {
                    cp = b;
                }
                
                /* Map codepoint back to byte */
                output[output_len++] = byte_decoder[cp];
                j += consumed - 1;
            } else {
                /* Direct byte */
                output[output_len++] = byte_decoder[b];
            }
        }
    }
    
    return output_len;
}

/* Main entry point */
int main(int argc, char **argv)
{
    (void)mc_write_str(1, "GPT-2 BPE Tokenizer\n");
    (void)mc_write_str(1, "===================\n\n");
    
    if (argc < 2) {
        (void)mc_write_str(2, "Usage: bpe <model_dir> [text to encode]\n");
        (void)mc_write_str(2, "       bpe <model_dir> -d <id1> <id2> ...  (decode)\n");
        return 1;
    }
    
    /* Build paths */
    char encoder_path[512];
    char vocab_path[512];
    mc_u32 dir_len = (mc_u32)mc_strlen(argv[1]);
    
    mc_memcpy(encoder_path, argv[1], dir_len);
    encoder_path[dir_len] = '/';
    mc_memcpy(encoder_path + dir_len + 1, "encoder.json", 13);
    
    mc_memcpy(vocab_path, argv[1], dir_len);
    vocab_path[dir_len] = '/';
    mc_memcpy(vocab_path + dir_len + 1, "vocab.bpe", 10);
    
    /* Initialize byte encoder */
    init_byte_encoder();
    
    /* Load vocabulary and merges */
    if (load_encoder(encoder_path) < 0) return 1;
    if (load_merges(vocab_path) < 0) return 1;
    
    (void)mc_write_str(1, "\n");
    
    if (argc == 2) {
        (void)mc_write_str(1, "Ready. Provide text to encode or -d to decode.\n");
        return 0;
    }
    
    /* Check for decode mode */
    if (argc >= 3 && argv[2][0] == '-' && argv[2][1] == 'd') {
        /* Decode mode */
        mc_u32 ids[1024];
        mc_u32 id_count = 0;
        
        for (int i = 3; i < argc && id_count < 1024; i++) {
            mc_u32 id = 0;
            const char *s = argv[i];
            while (*s >= '0' && *s <= '9') {
                id = id * 10 + (mc_u32)(*s - '0');
                s++;
            }
            ids[id_count++] = id;
        }
        
        (void)mc_write_str(1, "Decoding ");
        mc_write_u64_dec(1, id_count);
        (void)mc_write_str(1, " tokens:\n");
        
        mc_u8 output[4096];
        mc_u32 output_len = decode(ids, id_count, output, sizeof(output) - 1);
        output[output_len] = 0;
        
        (void)mc_write_str(1, "Result: ");
        (void)mc_write_all(1, output, output_len);
        (void)mc_write_str(1, "\n");
    } else {
        /* Encode mode: concatenate all remaining args */
        mc_u8 text[MAX_TEXT_LEN];
        mc_u32 text_len = 0;
        
        for (int i = 2; i < argc; i++) {
            if (i > 2) {
                text[text_len++] = ' ';
            }
            const char *s = argv[i];
            while (*s && text_len < MAX_TEXT_LEN - 1) {
                text[text_len++] = (mc_u8)*s++;
            }
        }
        
        (void)mc_write_str(1, "Encoding: \"");
        (void)mc_write_all(1, text, text_len);
        (void)mc_write_str(1, "\"\n\n");
        
        mc_u32 ids[1024];
        mc_u32 id_count = encode(text, text_len, ids, 1024);
        
        (void)mc_write_str(1, "Token count: ");
        mc_write_u64_dec(1, id_count);
        (void)mc_write_str(1, "\n");
        
        (void)mc_write_str(1, "Token IDs: ");
        for (mc_u32 i = 0; i < id_count; i++) {
            if (i > 0) (void)mc_write_str(1, " ");
            mc_write_u64_dec(1, ids[i]);
        }
        (void)mc_write_str(1, "\n\n");
        
        /* Decode back to verify */
        mc_u8 decoded[4096];
        mc_u32 decoded_len = decode(ids, id_count, decoded, sizeof(decoded) - 1);
        decoded[decoded_len] = 0;
        
        (void)mc_write_str(1, "Decoded: \"");
        (void)mc_write_all(1, decoded, decoded_len);
        (void)mc_write_str(1, "\"\n");
    }
    
    return 0;
}
