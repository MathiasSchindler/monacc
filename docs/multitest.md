# Multitoolchain Matrix (monacc vs gcc vs clang)

This document describes the current multi-toolchain “matrix” test harness, what it produces, and what’s left to do.

## Rationale

- **Correctness across compilers:** Tools should build and run cleanly with monacc, gcc, and clang. If they don’t, it signals gaps in portability or language surface coverage.
- **Size + simplicity:** Long-term, monacc-built binaries should be competitive with gcc/clang for size, static linking, and stripped outputs.
- **Self-reliance:** We keep “make” + “make test” as the primary UX. Extra validation is opt-in to avoid slowing day-to-day workflows.
- **Dogfood our userland:** Smoke-test the produced `bin/<tc>/sh` as a *binary under test*. The matrix orchestration itself runs under host `sh` for now because `bin/sh` is intentionally minimal.
- **Syscall-only ethos:** Maintain the project’s philosophy: static, syscall-level binaries, minimal dependencies, single-platform focus (Linux x86_64).

## Scope

- Build the userland tools with multiple toolchains: monacc, gcc, clang.
- Run a fast smoke test suite per toolchain.
- Collect size metrics (bytes per binary).
- Remain an **opt-in** path within `make test` (e.g., `MULTI=1 make test`), no new top-level targets required.

## Current Status

- **Implemented:** `MULTI=1 make test` builds the tool matrix, runs smoke tests, writes TSV reports, and generates an HTML report.
- **Orchestration:** runs under host `sh` (scripts are POSIX), because `bin/sh` is intentionally minimal.
- **Outputs (under `build/matrix/`):**
   - `build.tsv`: build status + mode + bytes (one row per toolchain/tool).
   - `report.tsv`: size table (toolchain/tool/bytes).
   - `report.html`: human-friendly table with per-tool red/green gradient shading.

## Milestones

1) **Harness & Shell Discipline**
   - ✅ POSIX-sh scripts live under `tests/matrix/`.
   - ✅ Orchestration runs via host `sh`.
   - ⏳ Future: make it runnable under `./bin/sh` once the shell supports variables/functions/substitution.

2) **Build Matrix (Baseline)**
   - ✅ Builds tools into `bin/<tc>/tool`.
   - ✅ Toolchains auto-detected: `monacc` + versioned `gcc-*` and `clang-*` found on PATH.
   - ✅ Hosted toolchains are built **static-first** with fallback to non-static; build mode is recorded.
   - ✅ Hosted flags tuned for small binaries (freestanding, no builtins, no PIE, `--gc-sections`, `-s`, `--build-id=none`, `-z noseparate-code`, etc.).

3) **Smoke Tests per Toolchain**
   - ✅ Implemented smoke tests per toolchain using the built `bin/<tc>/sh` as the runner.
   - ✅ Includes basic sanity (`echo`, `true/false`), `sh -c`, a pipe (`printf | grep | sed | wc`), `test`/`[`, and `ls`.

4) **Size Reporting**
   - ✅ Emits TSV bytes via `tests/matrix/size-report.sh`.
   - ✅ Emits a build report TSV via `tests/matrix/build-matrix.sh`.
   - ✅ Generates `build/matrix/report.html` with per-tool red/green gradient shading (min=green, max=red).
   - ⏳ Future: optional section-size reporting (e.g. `size -A`, `readelf -S`) when available.

5) **Integration Switch**
   - ✅ Wired into `make test` behind `MULTI=1`:
     - build: `tests/matrix/build-matrix.sh`
     - smoke tests: `tests/matrix/test-matrix.sh`
     - TSV size report: `tests/matrix/size-report.sh > build/matrix/report.tsv`
     - HTML report: `tests/matrix/tsv-to-html.sh --out build/matrix/report.html`

6) **Quality & Coverage**
   - ✅ “Best size per tool” is already highlighted in HTML (per-row gradient + min/max cues).
   - ⏳ Future: optional summary (counts, averages/medians) and trend tracking.

7) **Shell Capability Gap Closure**
   - ⏳ Still pending: `bin/sh` does not yet run the orchestration scripts.
   - Note: the *tested* shell for each toolchain is `bin/<tc>/sh` during smoke testing.

## Philosophy Alignment

- **Single UX:** Keep `make` / `make test` as the only entrypoints; matrix is opt-in to avoid friction.
- **Syscalls-only, static-first:** Prefer static, stripped outputs; allow graceful fallback to keep the signal flowing.
- **Portability discipline:** If gcc/clang fail, it’s a portability or surface coverage issue to fix; if monacc lags in size, it’s a performance/optimization gap to close.
- **Small, testable steps:** Fast smoke first; deeper tests can be layered later.
- **Dogfooding:** Run through `./bin/sh`; improve it as needed rather than quietly switching to host shells.

## Implementation Notes (concise)

- Scripts (POSIX sh) under `tests/matrix/`:
   - `build-matrix.sh`: builds tools for each toolchain into `bin/<tc>/` and writes `build/matrix/build.tsv`.
   - `test-matrix.sh`: runs smoke tests per toolchain (using `bin/<tc>/sh` where available).
   - `size-report.sh`: emits `toolchain<TAB>tool<TAB>bytes` to stdout (Makefile redirects to `build/matrix/report.tsv`).
   - `tsv-to-html.sh`: converts the two TSV files into `build/matrix/report.html`.
- Orchestration uses host `sh` (not `./bin/sh`).
- Matrix builds can be parallelized:
   - `make -jN MULTI=1 test` is honored (matrix scripts read `MAKEFLAGS`).
   - Or set `MATRIX_JOBS=N` to force a specific job count.
- Note on `awk`: the HTML generator prefers `./bin/awk` only if it supports required features; otherwise it uses system `awk`.

## Success Criteria

- ✅ `MULTI=1 make test` completes on a clean tree using host `sh`.
- All tools build on monacc/gcc/clang (with any static fallback noted).
- Smoke tests pass per toolchain.
- ✅ TSV + HTML report generated with per-tool, per-toolchain data; easy to spot best/worst per tool.
- No regressions to the existing `make` / `make test` experience when `MULTI` is unset.