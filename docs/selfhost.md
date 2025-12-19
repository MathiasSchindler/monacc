# monacc self-hosting roadmap

Date: 2025-12-18

This document describes a **series of concrete, testable steps** to advance monacc self-hosting from “the compiler can compile itself” to a **closed-loop build and test environment** that can run under monacc-built tooling.

The goal is to make progress in small increments, with regression probes at each stage.

---

## Definitions

- **Stage 0 (host)**: build `bin/monacc` with host `cc`.
- **Stage 1 (self)**: build `bin/monacc-self` using `bin/monacc`.
- **Stage 2 (self²)**: build `bin/monacc-self2` using `bin/monacc-self`.
- **Stage 3 (self³)**: build `bin/monacc-self3` using `bin/monacc-self2`.

Two orthogonal “internalization” axes:

- **Assembler axis**
  - internal ELF object emitter (default)
  - external `as` (bring-up/debug: `--as <path>` or `--toolchain <dir>`)

- **Linker axis**
  - internal linker (default)
  - external `ld` (bring-up/debug: `--ld <path>` or `--toolchain <dir>`)

When this document says “fully internal”, it means the default mode (equivalent to `--emit-obj --link-internal`).

---

## Current state (as of 2025-12-18)

- `make test` passes (examples + tools + probes).
- Stage 1 works (self-host build succeeds).
- Stage 2 works: `bin/monacc-self2` builds and can compile+run a representative example set.
- Stage-2 gating exists and passes when enabled: `SELFTEST_STAGE2=1 make test`.
- Stage 2 can also be run as a simple smoke test: `make selfhost2-smoke`.
- An opt-in stage-2 “fully internal” probe exists and passes:
  - `SELFTEST_STAGE2=1 SELFTEST_STAGE2_INTERNAL=1 make test`
- Stage 3 works and has an opt-in probe: `SELFTEST_STAGE3=1 make test`.

---

## Guiding principle

Treat self-hosting as a ladder:

1. **Buildability** (can produce the next stage binary)
2. **Runnability** (the next stage binary runs at all)
3. **Functionality** (the next stage can compile a small corpus)
4. **Equivalence** (stage N and stage N+1 behave the same on the corpus)
5. **Closure** (build/test scripts can run under monacc-built userland)

Each rung should have:
- a repeatable command
- a regression probe (ideally in `make test` behind a toggle)
- a minimal failing reproducer when broken

---

## Step-by-step plan

### Step 1 — Keep Stage 1 healthy and measurable

**Goal:** never regress Stage 1.

Commands:
- `make selfhost`
- `SELFTEST=1 make test` (informational probe)
- `SELFTEST_EMITOBJ=1 make test` (gating probe for `--emit-obj` under SELFHOST constraints)

Expected results:
- `bin/monacc-self` builds.
- `tests/compiler/selftest.sh` logs OK.
- `tests/compiler/selftest-emitobj.sh` passes.

Notes:
- Stage 1 being healthy is the prerequisite for debugging stage 2.


### Step 2 — Make Stage 2 a first-class probe (even if failing)

**Goal:** make stage-2 failures visible and reproducible, without blocking unrelated work.

Commands:
- `make selfhost2` (builds stage-2 compiler)
- `make selfhost2-smoke` (compile+run `examples/hello.c` using stage-2)
- `tests/compiler/selftest-stage2.sh` (non-blocking probe; logs failures)

Expected results (eventually):
- `selfhost2-smoke: OK`
- `selftest-stage2: run: OK`

Current status:
- stage-2 probe is green when enabled (strict gating works).


### Step 3 — Localize the Stage-2 crash with trace checkpoints

**Goal:** identify which subsystem is failing in stage 2.

Add a low-cost tracing mechanism that can be enabled at runtime:

- Option A (preferred): env var `MONACC_TRACE=1`
- Option B: CLI flag `--trace-selfhost`

Trace points should be coarse and stable, e.g.:
- `TRACE: read input`
- `TRACE: preprocess start/end`
- `TRACE: parser init`
- `TRACE: parse_program start/end`
- `TRACE: codegen start/end`
- `TRACE: assemble start/end` (for `--emit-obj`)
- `TRACE: link start/end` (internal/external)

Then run:
- `./bin/monacc-self2 examples/hello.c -o /tmp/x` (external as/ld)
- `MONACC_TRACE=1 ./bin/monacc-self2 ...` and see the last checkpoint

Notes:
- `MONACC_TRACE=1` enables tracing via env var.
- `--trace-selfhost` forces tracing on (useful when debugging re-exec paths).

Why this works:
- stage-2 crashes very early; you need to know whether it dies in preprocess vs parse vs allocation vs output.


### Step 4 — Produce a minimal reproducer (selfhost regression test)

**Goal:** reduce the bug to a small input that demonstrates the miscompile.

Approach:
- If the crash occurs compiling `examples/hello.c`, the bug is likely in shared compiler runtime/helpers.
- If the crash occurs only when compiling some compiler translation unit, extract that unit or the triggering construct.

Tactics:
- Build stage 2 with progressively smaller input sets:
  - compile only `compiler/monacc_front.c`
  - then add one file at a time until stage 2 becomes unstable
- If the crash is triggered by compiling a particular `.c`, reduce it by deleting unrelated functions while preserving the crash.

Deliverable:
- Add `examples/selfhost_regress_<name>.c` (or a small suite) that reliably triggers the bug.
- Add it to `EXAMPLES` once fixed.


### Step 5 — Add strict stage-2 gating (once stable)

**Goal:** ensure stage-2 never silently regresses again.

Mechanism:
- Add `SELFTEST_STAGE2=1` to `make test` (default off at first).
- When stable for a while, consider enabling it by default in CI-style runs.

Strict checks to include:
- Stage-2 can compile+run a representative example set.
- Optional: stage-2 can compile monacc itself to objects (`-c`) for a subset of files.


### Step 6 — Flip Stage-2 to the fully internal pipeline

**Goal:** stage-2 works with `--emit-obj --link-internal`.

Commands:
- `make selfhost2 SELFHOST2_LINKINT=1`
- `make selfhost2-smoke SELFHOST2_LINKINT=1`
- Optional probe: `SELFTEST_STAGE2=1 SELFTEST_STAGE2_INTERNAL=1 make test`

Notes:
- This step is intentionally later. First, fix stage-2 correctness; then internalize.
- Implementation detail: for `--link-internal` on multiple `.c` inputs, monacc links in a fresh process using the emitted `.o` files (and `--link-internal` also accepts `.o` inputs directly).


### Step 7 — Stage-3 equivalence (optional but powerful)

**Goal:** demonstrate “compiler bootstrapping convergence”.

Idea:
- Build `bin/monacc-self3` using `bin/monacc-self2`.
- Compare behavior (and optionally codegen output) between stage-2 and stage-3 on a corpus.

Commands:
- `make selfhost3`
- `make selfhost3-smoke`
- Optional probe: `SELFTEST_STAGE3=1 make test`

Small, practical equivalence tests:
- Both compilers compile `examples/*.c` and produced binaries behave identically.
- Optionally compare normalized assembly for a small set (ignore label numbering).

This is not required for usability, but it’s a strong confidence signal.


### Step 8 — Close the loop: build and test using monacc-built tools

**Goal:** run build/test flows under `bin/sh` and monacc-built tools (not host `/bin/sh`, not host coreutils).

Phased closure plan:

1. **Tests under `bin/sh`**
   - Make `make test` invoke scripts via `bin/sh` where practical.
   - Ensure scripts don’t rely on bashisms unless explicitly documented.

  Bring-up probe (very small):
  - `make binsh-smoke`
  - `make binsh-tools-smoke`
  - `make closure-smoke`
  - `SELFTEST_BINSHELL=1 SELFTEST_BINSHELL_TOOLS=1 make test`

  Heavier closure probe (still opt-in):
  - `make selfcontained-build-smoke`
  - `SELFTEST_BINSHELL_BUILD=1 make test`

  Note: `bin/sh` supports basic variables (`NAME=VALUE`, `$NAME`, `$1`, `$#`, `$@`).
  It still intentionally lacks `$(...)` command substitution.

2. **Minimal host dependency set**
   - Keep only the host `cc` for bootstrapping.
   - Ensure the rest of the build can be driven by monacc-built tooling.

3. **Optional: initramfs/QEMU closure**
   - Use `initramfs` to boot a tiny environment and run a scripted build/test.

Deliverable at the end:
- A documented command like: `bin/sh tests/closure/selfcontained-build.sh` that rebuilds monacc and runs tests.

### Toward “selfhost + ./bin/sh” as the default

The long-term objective is for the *default* developer workflow (`make` / `make test`)
to primarily exercise:
- monacc-built toolchain pieces (as early as feasible after the stage-0 bootstrap)
- `./bin/sh` as the script runner wherever it’s practical

To get there without destabilizing daily work, the safest path is:

1. **Centralize host shell dependencies and migrate callsites gradually**
   - The Makefile exposes `HOST_SH` and `HOST_BASH` so we can replace hard-coded
     `sh`/`bash` callsites one-by-one.
   - Early phase: keep defaults (`HOST_SH=sh`, `HOST_BASH=bash`) and only switch
     specific probes to `./bin/sh` behind toggles.

2. **Increase `./bin/sh` compatibility driven by real regressions**
   - Add shell features only when needed by meaningful tests (not theoretical POSIX completeness).
   - Pair every new feature with a regression under `tests/tools/binsh-*.sh`.

3. **Flip defaults after soak time**
   - First make probes “strict” in CI-style runs, then enable by default.
   - Eventually: enable stage-2/3 probes and the `./bin/sh` closure probes by default,
     and move most Makefile-invoked scripts onto `HOST_SH=./bin/sh`.

---

## Debugging toolbox (practical)

When stage 2 crashes:

- Use syscall tracing:
  - `strace -f -o build/trace.txt ./bin/monacc-self2 ...`
- Use trace checkpoints (Step 3).
- Temporarily disable optimizations for stage-1 build of the compiler-under-test:
  - build `bin/monacc` with `DEBUG=1 LTO=0` to reduce optimizer-induced miscompiles when narrowing down.

If the crash is in generated code:
- Force external ld vs internal ld to isolate.
- Force external as vs `--emit-obj` to isolate.

---

## Milestones checklist

- [x] Stage 1: `bin/monacc-self` builds and compiles+runs example set
- [x] Stage 2: `bin/monacc-self2` builds and compiles+runs `examples/hello.c`
- [x] Stage 2: gateable `SELFTEST_STAGE2=1 make test` passes
- [x] Stage 2 fully internal: `--emit-obj --link-internal` works end-to-end
- [x] Stage 3 convergence (optional)
- [ ] `make test` scripts runnable under `bin/sh`
- [ ] Self-contained build script runnable under monacc-built tools
