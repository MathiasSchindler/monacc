````markdown
# GPT-2 Inference Engine for monacc

## Project Goal

Build a complete GPT-2 117M inference engine that:
- Uses **no C library** - only raw Linux syscalls
- Targets **Linux x86_64**
- Compiles with **monacc** (a self-hosting C compiler)
- Demonstrates that the GPT-2 model works end-to-end

## monacc Compiler Constraints

The monacc compiler previously had several limitations that required workarounds.
As of 2025-12-19, float support (including comparisons and call/return ABI) has improved significantly; see `docs/float.md` for details.

### Syntax Limitations
1. **Macro expansion issues with function-like macros (multi-argument macros)**
   ```c
   // WRONG: #define KV_IDX(l,p,i) ((l)*CTX_EMBD + (p)*N_EMBD + (i))
   // CORRECT: Use inline functions
   static int kv_idx(int layer, int pos, int i) {
      return (int)((mc_u32)layer * g_ctx_embd + (mc_u32)pos * g_n_embd + (mc_u32)i);
   }
   ```

2. **Struct keyword required (standard C unless typedef'd)**
   ```c
   // WRONG: mc_stat st;
   // CORRECT: struct mc_stat st;
   ```

### Float feature status (practical)

The compiler has solid support for **in-function float arithmetic**, and (as of 2025-12-19) supports practical float comparisons and conversions needed for inference kernels:

- **Arithmetic inside a function works well:** `+ - * /`, accumulation loops, dot-product style loops, and float loads/stores (as exercised by `tests/compiler/float_minimal.c`).
- **Float comparisons via C operators work:** `<`, `>`, `<=`, `>=`, `==`, `!=` on `float` assemble and run.
- **Casts used directly as call arguments work:** patterns like `id_int((int)3.7f)` and `id_float((float)42)` are supported.

### Compilation Command
```bash
./bin/monacc --emit-obj --link-internal -I core \
   tools/gpt2.c core/mc_io.c core/mc_str.c core/mc_fmt.c core/mc_snprint.c core/mc_mathf.c core/mc_start_env.c \
   -o build/gpt2_monacc
```

Notes:
- `core/mc_fmt.c` provides the `mc_parse_*` helpers used for CLI argument parsing.
- The binary is typically written to `build/` during development.

## Architecture

### Components

1. **Checkpoint Converter** (`tools/ckpt2bin.c`) ✅ Complete
   - Reads TensorFlow checkpoint files (index + data)
   - Outputs a simple binary format for inference (v2 f32 or v3 quantized)

2. **BPE Tokenizer** (`tools/bpe.c`) ✅ Complete  
   - Parses `encoder.json` and `vocab.bpe`
   - Encodes text to token IDs
   - Decodes token IDs back to text

3. **Inference Engine** (`tools/gpt2.c`) ✅ Complete
   - Loads model from v2 (f32) or v3 (quantized) format
   - Implements transformer forward pass
   - Generates tokens autoregressively
   - Integrates the tokenizer so you can pass **text** and receive **text** output

### GPT-2 117M Model Parameters
| Parameter | Value |
|-----------|-------|
| n_vocab   | 50257 |
| n_ctx     | 1024  |
| n_embd    | 768   |
| n_head    | 12    |
| n_layer   | 12    |

### Binary Format (`gpt2.bin`)

**Header (64 bytes):**
| Offset | Size | Field |
|--------|------|-------|
| 0      | 4    | Magic: "GPT2" (0x32545047 little-endian) |
| 4      | 4    | Version: 2 (f32) or 3 (quantized) |
| 8      | 4    | n_vocab |
| 12     | 4    | n_ctx |
| 16     | 4    | n_embd |
| 20     | 4    | n_head |
| 24     | 4    | n_layer |
| 28     | 36   | Reserved (padding to 64 bytes); in v3: `reserved[0]=qtype`, `reserved[1].bit0=wte_quantized` |

**Quantization (v3):**
- `qtype=1` → q8 weights
- `qtype=2` → q4 weights
- Quantized matrices are stored row-by-row as an interleaved block:
   - `scale` (float32)
   - quantized row bytes (q8: `in_dim` bytes, q4: `ceil(in_dim/2)` bytes, signed two's complement)
- If `wte` is quantized, the file includes **pad-to-16 bytes after the `wte` block** so `wpe` (float32) starts 16-byte aligned (required for monacc on some code paths); `gpt2` validates this padding and will error if it’s missing.

**Weights (in order):**
1. `wte` - Token embeddings: [n_vocab × n_embd] floats
2. `wpe` - Position embeddings: [n_ctx × n_embd] floats
3. Per layer (×n_layer):
   - `ln1_g`, `ln1_b` - LayerNorm 1 gamma/beta
   - `attn_qkv_w`, `attn_qkv_b` - Attention QKV projection (matrix stored transposed for row-major matmul)
   - `attn_proj_w`, `attn_proj_b` - Attention output projection (matrix stored transposed for row-major matmul)
   - `ln2_g`, `ln2_b` - LayerNorm 2 gamma/beta
   - `mlp_fc_w`, `mlp_fc_b` - MLP fully-connected (matrix stored transposed for row-major matmul)
   - `mlp_proj_w`, `mlp_proj_b` - MLP projection (matrix stored transposed for row-major matmul)
4. `ln_f_g`, `ln_f_b` - Final LayerNorm

Total size depends on model + quantization.

In this repo the generated file is typically named `gpt2_v2.bin` (f32) or `gpt2_q8.bin` / `gpt2_q4.bin` (quantized).

## Quantized models (q8 / q4)

### Generate
```bash
./build/ckpt2bin_gcc --quantize q8 117M build/gpt2_q8.bin
./build/ckpt2bin_gcc --quantize q4 117M build/gpt2_q4.bin

# 355M (if the data file is zipped, unzip first)
unzip -n 355M/model.ckpt.data-00000-of-00001.zip -d 355M
./build/ckpt2bin_gcc --quantize q8 355M build/gpt2_355M_q8.bin
./build/ckpt2bin_gcc --quantize q4 355M build/gpt2_355M_q4.bin
```

### Run
```bash
./build/gpt2_gcc --raw --text build/gpt2_q8.bin "Hello, my name is"
./build/gpt2_gcc --raw --text build/gpt2_q4.bin "Hello, my name is"

./build/gpt2_gcc --raw --tokenizer-dir 355M --text build/gpt2_355M_q8.bin "Hello, my name is"
./build/gpt2_gcc --raw --tokenizer-dir 355M --text build/gpt2_355M_q4.bin "Hello, my name is"
```

Notes:
- q8 is generally much higher quality than q4 with this simple per-row scaling scheme.
- For q4, this repo currently keeps `wte` in float32 (but quantizes the large per-layer matrices) for better output quality.

## Implementation Details

### Math Functions (no libm)
Since we can't use libm, we implement our own:

- **`mc_expf(x)`**: Taylor series with range reduction
- **`mc_sqrtf(x)`**: Newton-Raphson iteration
- **`mc_tanhf(x)`**: Computed via `(exp(2x) - 1) / (exp(2x) + 1)`

### Memory Management
- Model weights: Memory-mapped from file using `mmap()`
- Activation buffers: Anonymous `mmap()` allocations sized from the model header
- KV cache: Anonymous `mmap()` allocations sized from the model header

### Syscalls Used
- `openat` - Open files
- `fstat` - Get file size
- `mmap` - Map model file into memory
- `read` - Read encoder.json, vocab.bpe
- `write` - Output text
- `close` - Close file descriptors
- `exit` - Program termination

## Current Status

### Completed ✅
- [x] Checkpoint converter (`ckpt2bin.c`)
- [x] Binary model file generated (`gpt2_v2.bin`, ~497MB)
- [x] BPE tokenizer with encode/decode
- [x] Tokenizer verified: "Hello, world!" → [15496, 11, 995, 0]
- [x] GPT-2 inference engine runs end-to-end under monacc and gcc
- [x] Text-mode generation (tokenizer integrated into `gpt2`)

### CLI Usage

Token-id mode (original interface):
```bash
./build/gpt2_monacc ./gpt2_v2.bin 15496 11 995 0
```

Text mode (prompt from arguments):
```bash
./build/gpt2_monacc ./gpt2_v2.bin --tokenizer-dir 117M --text Hello world
```

Text mode (prompt from stdin):
```bash
echo "Hello world" | ./build/gpt2_monacc ./gpt2_v2.bin --tokenizer-dir 117M --stdin
```

Raw mode (print only generated text; suitable for piping):
```bash
./build/gpt2_monacc --raw ./gpt2_v2.bin --tokenizer-dir 117M --text Hello world
```

Generation controls:
- `--max-tokens N` (default 20)
- `--temperature T` (default 1.0; use `--temperature 0` for greedy)
- `--top-k K` (default 40; use `--top-k 0` for full vocab)
- `--top-p P` (default 0 = off; nucleus sampling in (0,1])
- `--seed S` (optional; otherwise seeds from `getrandom`)

Example:
```bash
./build/gpt2_monacc --raw --temperature 0.8 --top-p 0.9 --seed 123 ./gpt2_v2.bin --tokenizer-dir 117M --text Hello world
```

## Testing

### Float Arithmetic Test

Float arithmetic was verified to produce identical results between monacc and gcc:

```bash
# Build and run with monacc
./bin/monacc --emit-obj --link-internal -I core tests/compiler/float_minimal.c \
    core/mc_io.c core/mc_str.c core/mc_snprint.c core/mc_start_env.c \
    -o build/float_test/float_minimal
./build/float_test/float_minimal
```

**Note**: this project avoids libm/libc entirely; floating-point functionality is provided by small local helpers (see `core/mc_mathf.c`).

### Tokenizer Test
```bash
./tools/bpe 117M "Hello, world!"
# Output includes: Token IDs: 15496 11 995 0
```

### v3 q8 Padding Regression Test

This checks that v3 q8 models include the required pad-to-16 bytes after quantized `wte` (to keep `wpe` 16-byte aligned). It is wired into `make test` but is skipped unless you provide a model path:

```bash
GPT2_V3_Q8_MODEL=/path/to/gpt2_q8.bin make test
```

### Inference Test
```bash
./build/gpt2_monacc ./gpt2_v2.bin --tokenizer-dir 117M --text "Hello, world!"
# Expected: Prints a plausible continuation in text
```

## Files

| File | Description | Status |
|------|-------------|--------|
| `tools/ckpt2bin.c` | TensorFlow checkpoint to binary converter | ✅ Complete |
| `tools/bpe.c` | BPE tokenizer | ✅ Complete |
| `tools/gpt2.c` | Inference engine (token IDs + text mode) | ✅ Complete |
| `gpt2_v2.bin` | Converted model weights (format v2) | ✅ Generated |
| `117M/` | Original GPT-2 117M checkpoint | Source data |

## References

- [GPT-2 Paper](https://cdn.openai.com/better-language-models/language_models_are_unsupervised_multitask_learners.pdf)
- [OpenAI GPT-2 Repository](https://github.com/openai/gpt-2)
- [Andrej Karpathy's llm.c](https://github.com/karpathy/llm.c)

````

3. **Inference Engine** (`tools/gpt2.c`) 🔄 In Progress
   - Loads model from `gpt2.bin`
   - Implements transformer forward pass
   - Generates tokens autoregressively

### GPT-2 117M Model Parameters
| Parameter | Value |
|-----------|-------|
| n_vocab   | 50257 |
| n_ctx     | 1024  |
| n_embd    | 768   |
| n_head    | 12    |
| n_layer   | 12    |

### Binary Format (`gpt2.bin`)

**Header (64 bytes):**
| Offset | Size | Field |
|--------|------|-------|
| 0      | 4    | Magic: "GPT2" (0x32545047 little-endian) |
| 4      | 4    | Version: 1 |
| 8      | 4    | n_vocab |
| 12     | 4    | n_ctx |
| 16     | 4    | n_embd |
| 20     | 4    | n_head |
| 24     | 4    | n_layer |
| 28     | 36   | Reserved (padding to 64 bytes) |

**Weights (in order):**
1. `wte` - Token embeddings: [n_vocab × n_embd] floats
2. `wpe` - Position embeddings: [n_ctx × n_embd] floats
3. Per layer (×12):
   - `ln1_g`, `ln1_b` - LayerNorm 1 gamma/beta
   - `attn_qkv_w`, `attn_qkv_b` - Attention QKV projection
   - `attn_proj_w`, `attn_proj_b` - Attention output projection
   - `ln2_g`, `ln2_b` - LayerNorm 2 gamma/beta
   - `mlp_fc_w`, `mlp_fc_b` - MLP fully-connected
   - `mlp_proj_w`, `mlp_proj_b` - MLP projection
4. `ln_f_g`, `ln_f_b` - Final LayerNorm

Total size: ~497 MB

## Implementation Details

### Math Functions (no libm)
Since we can't use libm, we implement our own:

- **`mc_expf(x)`**: Taylor series with range reduction
- **`mc_sqrtf(x)`**: Newton-Raphson iteration
- **`mc_tanhf(x)`**: Computed via `(exp(2x) - 1) / (exp(2x) + 1)`

### Memory Management
- Model weights: Memory-mapped from file using `mmap()`
- Activation buffers: Static allocation (no malloc)
- KV cache: Flattened 1D array with helper function for indexing

### Syscalls Used
- `openat` - Open files
- `fstat` - Get file size
- `mmap` - Map model file into memory
- `read` - Read encoder.json, vocab.bpe
- `write` - Output text
- `close` - Close file descriptors
- `exit` - Program termination

## Current Status

### Completed ✅
- [x] Checkpoint converter (`ckpt2bin.c`)
- [x] Binary model file generated (`gpt2.bin`, 497MB)
- [x] BPE tokenizer with encode/decode
- [x] Tokenizer verified: "Hello, world!" → [15496, 11, 995, 0]

### In Progress 🔄
- [ ] GPT-2 inference engine compiles
- [ ] Forward pass produces correct values
- [ ] Token generation works

### Known Issues
- Float arithmetic produces NaN in attention score computation
- Need to verify monacc's float handling matches gcc/clang

Additional known float-related issues observed during testing:
- Some float↔int casts appear to miscompile when used directly in call arguments; storing the cast into a temporary first is a reliable workaround.

## Testing

### Float Arithmetic Test

Float arithmetic was verified to produce identical results between monacc and gcc:

```bash
# Build and run with monacc
./bin/monacc --emit-obj --link-internal -I core examples/float_arith.c \
   -o build/float_test/float_arith
./build/float_test/float_arith

# Output:
# === Float Tests ===
# 1.0 + 2.0: 30000      (3.0)
# 5.5 - 3.2: 23000      (2.3)
# 2.5 * 4.0: 100000     (10.0)
# 10.0 / 4.0: 25000     (2.5)
# -3.0 * 4.0: -120000   (-12.0)
# 0.1 * 0.1: 100        (0.01)
# sum 10x0.1: 10000     (1.0)
# (float)42: 420000     (42.0)
# (int)3.7: 3
# sum array: 120000     (12.0)
# dot product: 50000    (5.0)
# === Done ===
```

**Note**: monacc's internal assembler supports `jp/jnp` now, so float comparisons assemble correctly. Bit-pattern tricks are still useful if you want to avoid NaN/unordered semantics entirely.

### Tokenizer Test
```bash
./tools/bpe 117M/encoder.json 117M/vocab.bpe encode "Hello, world!"
# Output: 15496 11 995 0
```

### Inference Test
```bash
./tools/gpt2 gpt2.bin 15496 11 995 0
# Expected: Generate continuation tokens
```

## Files

| File | Description | Status |
|------|-------------|--------|
| `tools/ckpt2bin.c` | TensorFlow checkpoint to binary converter | ✅ Complete |
| `tools/bpe.c` | BPE tokenizer | ✅ Complete |
| `tools/gpt2.c` | Inference engine | 🔄 In progress |
| `gpt2.bin` | Converted model weights | ✅ Generated |
| `117M/` | Original GPT-2 117M checkpoint | Source data |

## References

- [GPT-2 Paper](https://cdn.openai.com/better-language-models/language_models_are_unsupervised_multitask_learners.pdf)
- [OpenAI GPT-2 Repository](https://github.com/openai/gpt-2)
- [Andrej Karpathy's llm.c](https://github.com/karpathy/llm.c)
