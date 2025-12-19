# GPT-2 Inference Engine for monacc

## Project Goal

Build a complete GPT-2 117M inference engine that:
- Uses **no C library** - only raw Linux syscalls
- Targets **Linux x86_64**
- Compiles with **monacc** (a self-hosting C compiler)
- Demonstrates that the GPT-2 model works end-to-end

## monacc Compiler Constraints

The monacc compiler has several limitations that must be worked around:

### Syntax Limitations
1. **No multiple declarations on one line**
   ```c
   // WRONG: float *a, *b;
   // CORRECT:
   float *a;
   float *b;
   ```

2. **No expressions with `*` in array size declarations**
   ```c
   // WRONG: float arr[3 * N_EMBD];
   // CORRECT: Use precomputed constants
   #define N_EMBD_X3 2304  /* 3 * 768 */
   float arr[N_EMBD_X3];
   ```

3. **Macro expansion issues with multi-argument macros**
   ```c
   // WRONG: #define KV_IDX(l,p,i) ((l)*CTX_EMBD + (p)*N_EMBD + (i))
   // CORRECT: Use inline functions
   static int kv_idx(int layer, int pos, int i) {
       return layer * CTX_EMBD + pos * N_EMBD + i;
   }
   ```

4. **Struct keyword required**
   ```c
   // WRONG: mc_stat st;
   // CORRECT: struct mc_stat st;
   ```

5. **NaN/unordered semantics in float comparisons**
   Comparisons like `a < b` are lowered via `ucomiss` + conditional branches, including parity branches (`jp/jnp`) for unordered (NaN) handling.

   **Update (2025-12-19):** monacc's internal assembler supports `jp/jnp`, so these comparisons assemble correctly. Bit-pattern tricks are still useful if you intentionally want to avoid NaN/unordered behavior.

### Float feature status (practical)

The compiler has solid support for **in-function float arithmetic**, but there are a few important edges that matter a lot for GPT-2:

- **Arithmetic inside a function works well:** `+ - * /`, accumulation loops, dot-product style loops, and float loads/stores (see `examples/float_arith.c`).
- **Float comparisons via C operators work:** comparisons emit `ucomiss` + conditional branches (including `jp/jnp` for unordered handling), and the internal assembler supports these now.
- **Float↔int casts used directly as call arguments are supported:** this used to be a fragile edge; it’s now fixed and covered by `examples/float_cast_callargs.c`.

- **SysV ABI for float calls (subset) works:** `float` parameters are passed in `%xmm0..%xmm7` (separate from integer args), and `float` returns use `%xmm0`.

### Compilation Command
```bash
./bin/monacc --emit-obj --link-internal -I core \
    tools/gpt2.c core/mc_io.c core/mc_str.c core/mc_snprint.c core/mc_start_env.c \
    -o tools/gpt2
```

## Architecture

### Components

1. **Checkpoint Converter** (`tools/ckpt2bin.c`) ✅ Complete
   - Reads TensorFlow checkpoint files (index + data)
   - Outputs a simple binary format for inference

2. **BPE Tokenizer** (`tools/bpe.c`) ✅ Complete  
   - Parses `encoder.json` and `vocab.bpe`
   - Encodes text to token IDs
   - Decodes token IDs back to text

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
