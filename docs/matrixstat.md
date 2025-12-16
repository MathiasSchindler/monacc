# matrixstat

`matrixstat` is a syscalls-only analysis tool that scans the compiler/tool matrix under `bin/*_*/` and emits **TSV** statistics about the *instruction-ish* byte patterns found in each binary.

It is designed to help answer questions like:
- “Which compiler variant emits the most `push/pop` (stack staging) across the whole tool suite?”
- “Which tools have unusually high `setcc` / `movsxd` counts under monacc?”
- “Does a change reduce `push/pop` globally, or only for one tool?”

This tool is intentionally **not** a full disassembler. It uses a small set of stable opcode-pattern counters that correlate well with codegen shape.

## Build

The binary is built like the other sysbox tools:

- `make bin/matrixstat`

(Or just `make` / `make test`, which build all tools.)

## Usage

### Scan all compiler directories (totals only)

- `./bin/matrixstat`

This prints one `__TOTAL__` row per compiler directory (e.g. `monacc_`, `gcc_15_`, `clang_20_`).

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
- `ret` – `C3` / `C2 imm16`.
- `jcc` – conditional branches (`0F 8?` and `7?`).
- `jmp` – unconditional branches (`E9` and `EB`).
- `setcc` – `0F 90..9F` (with/without REX).
- `movsxd` – `movsxd r64, r/m32` (`REX.W + 63` and a conservative `63` fallback).
- `syscall` – `0F 05`.

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
