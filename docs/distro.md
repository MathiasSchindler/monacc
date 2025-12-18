# Distro / Release Tarball Plan (v0.1)

This document describes a **small, reproducible “dist” script** that produces a **minimal release tarball** for `monacc` **release 0.1**.

The tarball should contain **only** what is needed to build:

1. the compiler (`bin/monacc`) with the host C compiler
2. all syscall-only tools (`bin/*`) using the newly built `bin/monacc`

No tests, no kernel, no examples, no docs, no build outputs.

## Output

- Script produces: `release/monacc-0.1.tar.gz`
- Optional additional artifact: `release/monacc-0.1-initramfs.cpio.gz`
- Tarball root directory: `monacc-0.1/`

Contents (only):

- `monacc-0.1/Makefile`
- `monacc-0.1/compiler/*.{c,h}`
- `monacc-0.1/core/*.{c,h}`
- `monacc-0.1/tools/*.{c,h}`

Notes:
- `core/` is included because it is part of the compiler+toolchain sources (shared `mc_*` runtime).
- The minimal `Makefile` is generated into the staging directory to avoid copying the full repo `Makefile` (which includes tests, selfhost probes, matrix, etc.).

## Script design

Add a repo script:

- `scripts/make-distro.sh`

Responsibilities:

1. Create `release/` if missing.
2. Create a temporary staging directory.
3. Copy **only** the required sources into `staging/monacc-0.1/...`.
4. Write a minimal `Makefile` into `staging/monacc-0.1/Makefile`.
5. Produce `tar.gz` into `release/`.
6. Optionally build the staged tree and pack an initramfs containing `/init` + `/bin/*`.
7. Clean up the staging directory.

### Optional initramfs

If enabled, the script will:

- run `make all` inside the staged distro
- create a minimal initramfs root with:
  - `/init` copied from the built `bin/init`
  - `/bin/*` containing the compiler and tools
  - empty `/dev`, `/proc`, `/sys` mount points
- pack it as `newc` cpio and gzip it to `release/monacc-<version>-initramfs.cpio.gz`

This allows booting the userland with an external Linux kernel (x86_64) and getting a working environment with the monacc `init` and `sh`.

### “Minimalist Makefile” requirements

The Makefile inside the tarball should:

- Build `bin/monacc` with host `cc` (gcc/clang), using the same approach as the repo:
  - `-nostartfiles -Wl,-e,_start`
  - include the small `core` subset required by the compiler runtime (`mc_start.c`, `mc_start_env.c`, etc.)
- Build tools with `./bin/monacc` using `--emit-obj --link-internal` by default.
- Provide:
  - `make` / `make all`
  - `make clean`

It must not:

- reference tests, docs, examples, kernel, or `build/` outputs
- require `bash`

### File selection rules

Strict include list:

- `compiler/*.c`, `compiler/*.h`
- `core/*.c`, `core/*.h`
- `tools/*.c`, `tools/*.h`

Strict exclude list (by omission):

- `bin/`, `build/`, `tests/`, `examples/`, `kernel/`, `docs/`, `scripts/`, `.git/`, editor configs

## Verification checklist

After running:

- `./scripts/make-distro.sh 0.1`

Verify:

1. Tarball exists: `release/monacc-0.1.tar.gz`
2. Tarball contains only the expected files:
   - `tar tzf release/monacc-0.1.tar.gz | sort`
3. Build from scratch:

```sh
mkdir -p /tmp/monacc-dist-test
cd /tmp/monacc-dist-test
rm -rf monacc-0.1
tar xzf /path/to/release/monacc-0.1.tar.gz
cd monacc-0.1
make
```

Expected:

- `bin/monacc` built via host `cc`
- tools built via `./bin/monacc`

## Reference implementation

See `scripts/make-distro.sh` for the concrete implementation.
