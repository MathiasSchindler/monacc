# matrixstat

`matrixstat` is a syscalls-only analysis tool that scans the compiler/tool matrix under `bin/*_*/` and emits **TSV** statistics about the *instruction-ish* byte patterns found in each binary.

It is designed to help answer questions like:
- “Which compiler variant emits the most `push/pop` (stack staging) across the whole tool suite?”
- “Which tools have unusually high `setcc` / `movsxd` counts under monacc?”
- “Does a change reduce `push/pop` globally, or only for one tool?”

This tool is intentionally **not** a full disassembler. It uses a small set of stable opcode-pattern counters that correlate well with codegen shape.

## Build

The binary is built like the other monacc tools:

- `make bin/matrixstat`

(Or just `make` / `make test`, which build all tools.)

## Usage

### Scan all compiler directories (totals only)

- `./bin/matrixstat`

This prints one `__TOTAL__` row per compiler directory (e.g. `monacc_`, `gcc_15_`, `clang_20_`).

### Matrix integration (recommended)

When you run `MULTI=1 make test`, the matrix harness now also writes:

- `build/matrix/matrixstat.tsv`

This is the per-tool TSV output of `matrixstat` for exactly the toolchains selected by the matrix run.

### Scan one compiler directory

- `./bin/matrixstat --only monacc_`

### Scan a single tool across all compilers

- `./bin/matrixstat --tool yes`

This is useful to compare opcode mix across compilers for one tool.

### Per-tool rows

- `./bin/matrixstat --per-tool`

This prints one row per tool **plus** a `__TOTAL__` summary row per compiler directory.

You can combine filters:

- `./bin/matrixstat --per-tool --only monacc_`
- `./bin/matrixstat --per-tool --tool sh`

### Show only top-N offenders

`--top FIELD N` prints only the top-N tools per compiler directory by the chosen counter (plus the `__TOTAL__` row). This is the fastest way to answer “what should I look at next?”

Examples:

- Top 20 `push` offenders under monacc:
	- `./bin/matrixstat --only monacc_ --top push 20`

- Top 30 `movsxd` offenders across each compiler dir:
	- `./bin/matrixstat --top movsxd 30`

- Top 15 `setcc` offenders for a single compiler dir:
	- `./bin/matrixstat --only monacc_ --top setcc 15`

	### Show top-N by density (`--top-ratio`)

	Raw counts tend to be dominated by the largest tools. `--top-ratio FIELD N` instead ranks by **density** (roughly: $FIELD / text\_bytes$), which is often better for finding “weirdly bad” codegen patterns in smaller programs.

	Examples:

	- Top 20 by `push` density under monacc:
		- `./bin/matrixstat --only monacc_ --top-ratio push 20`

	- Top 20 by `movsxd` density under monacc:
		- `./bin/matrixstat --only monacc_ --top-ratio movsxd 20`

	- Compare density offenders across all compilers:
		- `./bin/matrixstat --top-ratio setcc 15`

## Output format (TSV)

The output is tab-separated and begins with a header row:

- `compiler` – compiler directory name under `bin/` (e.g. `monacc_`, `gcc_15_`).
- `tool` – tool filename (e.g. `yes`) or `__TOTAL__`.
- `n_files` – number of files considered for this row.
- `n_ok` – number of files successfully scanned as ELF.
- `n_err` – number of files that could not be scanned (non-ELF, parse failure, mmap failure, etc.).
- `file_bytes` – total file size sum.
- `text_bytes` – total bytes scanned for opcode patterns (see “How scanning works”).
- `push` / `pop` – counts of register push/pop opcodes (`50..57`, `58..5F`, and REX forms for r8–r15).
- `call` – `E8 rel32` call sites.
- `icall` – indirect calls (`FF /2`).
- `ret` – `C3` / `C2 imm16`.
- `leave` – `C9`.
- `jcc` – conditional branches (`0F 8?` and `7?`).
- `jmp` – unconditional branches (`E9` and `EB`).
- `setcc` – `0F 90..9F` (with/without REX).
- `movsxd` – `movsxd r64, r/m32` (`REX.W + 63` and a conservative `63` fallback).
- `syscall` – `0F 05`.

Additional “compiler quality” counters:

- `prologue_fp` – frame-pointer prologues (`push rbp; mov rbp, rsp`).
- `stack_sub` / `stack_add` – stack pointer adjustments (`sub/add rsp, imm`).
- `stack_load` / `stack_store` – stack slot traffic proxy (common `mov` loads/stores from/to stack slots like `[rsp+disp]` and `[rbp+disp]`).
- `xor_zero` – `xor reg, reg` zeroing idiom.
- `mov_imm0` – `mov reg, 0` immediate-zero idiom.
- `lea` – `lea` usage density (addressing-mode/strength-reduction proxy).

Derived density columns (ppm-ish):

- `push_ppm`, `call_ppm`, `setcc_ppm`, `movsxd_ppm` – events per 1,000,000 `text_bytes`.

Scan context columns (to interpret signal/noise):

- `scan_mode` – `shdr` when scanning executable section headers (typically gcc/clang outputs), `phdr` when falling back to executable `PT_LOAD` segments (typical for monacc sectionless outputs), `mixed` when both were used.
- `n_exec_regions` – number of executable regions scanned for this row.
- `n_exec_off0` – number of executable regions whose file offset was 0 (common in minimal single-segment layouts; means ELF headers are included in scanned bytes).
- `exec_coverage_ppm` – `text_bytes * 1_000_000 / file_bytes` (high values indicate “we scanned most of the file”).
- `n_scan_shdr` / `n_scan_phdr` – how many files in this row were scanned via each method.

## `--top` fields

Valid `FIELD` values:

- `file_bytes`, `text_bytes`
- `push`, `pop`, `call`, `ret`, `jcc`, `jmp`, `setcc`, `movsxd`, `syscall`

These counters are intended to be compared **relative** (monacc vs gcc/clang), not treated as exact instruction counts.

## How scanning works

`matrixstat` prefers **section headers** when they are present:

- It scans `SHT_PROGBITS` sections with `SHF_EXECINSTR` set (typically `.text`).

Some binaries in this repository intentionally omit section headers (notably monacc-built outputs for size reasons). In that case, `matrixstat` falls back to **program headers**:

- It scans bytes in `PT_LOAD` segments with `PF_X` set.

### Important limitation

When scanning executable `PT_LOAD` bytes, the scanned region may include more than pure `.text` (for example, a minimal single-segment layout can include constants/data in the same segment). That means counts can include some false positives from non-code bytes.

For this reason:
- Prefer comparisons **within the same tool** across compilers (`--tool TOOL`) where non-code bytes are often similar.
- Use `matrixstat` to find *where to look next*, then confirm with `scripts/compare_codegen.sh --detail TOOL`.

## Incremental improvements (easy, high-value)

This section is a concrete backlog of **small, incremental** improvements that keep `matrixstat` fast and syscalls-only.

### 1) Improve correctness / signal-to-noise

These changes mainly reduce false positives from scanning raw bytes.

1. **Expose scan mode in the TSV**
	- Add a column like `scan_mode` with values `shdr` (section headers) vs `phdr` (program headers fallback).
	- This makes it obvious when counts may be noisier (single-segment layouts, embedded const/data in `PF_X`).

2. **Expose “coverage” context**
	- Add per-row columns such as `n_exec_regions` and `exec_bytes_scanned`.
	- Add derived ratio `text_coverage_ppm = text_bytes * 1_000_000 / file_bytes`.
	- This helps detect “we scanned more than pure code” quickly.

3. **Make output deterministic by default**
	- Sort compiler dirs and tool names before printing.
	- This makes `build/matrix/matrixstat.tsv` diff-friendly and makes regressions easier to spot.

4. **Strengthen filters for “real executables”**
	- In addition to ELF magic, validate `e_machine == x86_64` and accept only `ET_EXEC` / `ET_DYN`.
	- This prevents weird files under `bin/*_*/` (or accidental outputs) from polluting stats.

5. **Add an optional “more strict” scan mode**
	- Keep the current scan as the default (fast).
	- Add a flag like `--strict` that uses small boundary heuristics for the patterns you count:
		- validate operand-length expectations (e.g., `E8`/`E9` require imm32, `0F 8?` requires imm32)
		- require ModRM for patterns that need it
	- This is still far from a disassembler, but reduces random-byte matches significantly.

### 2) Add metrics that map more directly to compiler quality

These counters give more actionable signals about regalloc, lowering quality, and ABI/stack discipline.

1. **Stack frame/prologue counters (ABI + optimization maturity)**
	- Count `push rbp; mov rbp, rsp` prologues and `leave` epilogues.
	- Count stack allocation patterns: `sub rsp, imm` and `add rsp, imm`.
	- Helps answer: “are we using frame pointers everywhere?” and “how much stack churn do we emit?”.

2. **Stack slot traffic counters (spill pressure proxy)**
	- Count common `[rsp+disp]` load/store forms (requires minimal ModRM/SIB handling).
	- Helps identify tools where monacc is spill-heavy relative to gcc/clang.

3. **Zeroing idioms (teaches ‘what others do’)**
	- Count `xor reg, reg` vs `mov reg, 0`.
	- This is a classic, easy-to-spot codegen quality marker and correlates with missed peepholes.

4. **Indirect call/jump counts (thunks, PLT-ish shapes, missed devirtualization)**
	- Count `call r/m64` (`FF /2`) and common RIP-relative indirect jumps.
	- Useful to spot accidental dynamic-linkage shapes or unusual thunking.

5. **`lea` density (addressing-mode/strength-reduction proxy)**
	- Count `lea r64, m` (`8D /r` with/without REX.W).
	- Often correlates with how good the compiler is at folding address arithmetic.

6. **Built-in derived ratios (so you don’t have to post-process)**
	- Print ppm-style columns for a few key counters:
		- `push_ppm`, `call_ppm`, `movsxd_ppm`, `setcc_ppm` where `X_ppm = X * 1_000_000 / text_bytes`.
	- This makes “bad density outliers” easy to sort in a spreadsheet.

## Recommended workflows (for humans and LLMs)

### 1) Find global “shape” gaps

- `./bin/matrixstat | sort -k1,1`

Look for big deltas in `push/pop`, `movsxd`, and `setcc` for `monacc_` vs `gcc_15_` / `clang_20_`.

### 2) Pinpoint tool offenders

- `./bin/matrixstat --per-tool --only monacc_ | sort -t $'\t' -k8,8nr | head`

(Adjust sort column indices if you add/remove columns.)

### 3) Compare one tool across compilers

- `./bin/matrixstat --tool sh`

If monacc has much higher `push/pop` here, it supports focusing on call/arg lowering and stack staging patterns for that tool.

### 4) Confirm with disassembly diffs

- `./scripts/compare_codegen.sh --detail TOOL`

Use the detailed diff to locate the concrete codegen sequences that correspond to the higher-level counters.

## Extending matrixstat

Good incremental extensions (still syscalls-only) include:
- More opcode patterns that correlate with known bloat sources (e.g. `movzx`/`movsx` variants, `test`/`cmp` density).
- Per-function breakdown (requires parsing symbol tables; not available in section-header-less ELFs unless you add a sidecar map).
- Optional runtime syscall frequency stats by running matrix tests under `strace -c` (dynamic, input-dependent).
