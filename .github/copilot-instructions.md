# monacc Copilot instructions

## Build and test commands

- Full build (Linux default, parallel): `make -j 12`
- Build just the compiler bootstrap binary: `make bin/monacc`
- Build self-hosted compilers: `make selfhost` / `make selfhost2` / `make selfhost3`
- Full test suite: `make -s test`
- Matrix test + size comparison report (recommended, parallel): `MATRIX_SIZE_ONLY=1 MULTI=1 MATRIX_TCS="monacc gcc-15 clang-21" make test -j 12` (writes `build/matrix/report.tsv`)
- Run one compiler test directly: `bash tests/compiler/phase1-smoke.sh`
- Run one tools suite directly: `sh tests/tools/run.sh smoke`
- Run a specific gated self-hosting test group: `SELFTEST_STAGE2=1 make test` or `SELFTEST_STAGE3=1 make test`
- Optional repo guard checks used by `make test`:
  - `sh tests/repo/no-kernel-binutils-creep.sh .`
  - `sh tests/repo/function-overlap.sh .`

## High-level architecture

- The top-level build is a staged loop:
  1. host `cc` builds `bin/monacc` (Phase 0),
  2. `bin/monacc` builds syscall-only tools in `bin/` (Phase 1),
  3. self-host targets build `bin/monacc-self*` (Stages 1/2/3).
- `compiler/` is the monacc compiler implementation (driver, pp/lexer, parser/sema, codegen, ELF writer/reader, internal linker).
- `core/` provides shared `mc_*` runtime pieces used by compiler and tools.
- `tools/` contains syscall-only userland programs compiled by monacc; Makefile aliases `test -> [` and `readlink -> realpath`.
- `tests/` combines example-return-code checks, compiler self-tests, tool suites, and repo guard scripts under `make test`.
- `kernel/` is an optional experimental subproject and not required for normal compiler/tool builds.

## Repository-specific conventions

- Default toolchain path is internal object emission + internal linker; use `EMITOBJ=0` and/or `LINKINT=0` only for bring-up/debugging.
- `monacc` emits `_start` from the first input translation unit only; ensure the first source file is the one that should provide `main`/entry behavior.
- Example programs in `examples/` are test fixtures expected to return exit code `42`; many regressions are validated through this invariant.
- Test groups are controlled via `SELFTEST_*` variables in `Makefile` (enabled by default); prefer toggling only the needed group instead of editing scripts.
- Build/test scripts are being prepared for monacc-built shell usage; use `HOST_SH` / `HOST_BASH` knobs instead of hardcoding shell paths when modifying orchestration.
