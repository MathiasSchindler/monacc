#!/bin/sh
set -eu

# Build a minimal source tarball for a release.
# Output: release/monacc-<version>.tar.gz
# Optional: also produce an initramfs with built binaries.

VERSION=0.1.1
WANT_INITRAMFS=1
INITRAMFS_STRICT=0
INITRAMFS_INIT_NAME=init

for arg in "$@"; do
	case "$arg" in
		--no-initramfs)
			WANT_INITRAMFS=0
			;;
		--initramfs)
			WANT_INITRAMFS=1
			INITRAMFS_STRICT=1
			;;
		--init=*)
			INITRAMFS_INIT_NAME=${arg#--init=}
			;;
		-*)
			echo "usage: $0 [version] [--initramfs|--no-initramfs] [--init=<name>]" >&2
			echo "       --init=<name> chooses /init from bin/<name> (default: init)" >&2
			exit 2
			;;
		*)
			VERSION="$arg"
			;;
	esac
done

# Resolve repo root from this script location.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

OUT_DIR="$ROOT_DIR/release"
OUT_TAR="$OUT_DIR/monacc-$VERSION.tar.gz"
OUT_INITRAMFS_CPIO="$OUT_DIR/monacc-$VERSION-initramfs.cpio"
OUT_INITRAMFS="$OUT_DIR/monacc-$VERSION-initramfs.cpio.gz"

# Stage into a temporary directory.
# Prefer mktemp -d; fall back to a predictable path if needed.
if command -v mktemp >/dev/null 2>&1; then
	STAGE_BASE=$(mktemp -d "${TMPDIR:-/tmp}/monacc-dist.XXXXXX")
else
	STAGE_BASE="${TMPDIR:-/tmp}/monacc-dist.$$"
	mkdir -p "$STAGE_BASE"
fi

cleanup() {
	rm -rf "$STAGE_BASE"
}
trap cleanup EXIT INT TERM

STAGE_ROOT="$STAGE_BASE/monacc-$VERSION"
mkdir -p "$STAGE_ROOT" "$OUT_DIR"

# Add a minimal README for the release tarball.
# Use a quoted heredoc to avoid the shell expanding markdown backticks.
{
	printf '# monacc-%s (minimal distro)\n\n' "$VERSION"
	cat <<'EOF'
This tarball contains **a C compiler** and **a small suite of useful command-line tools**.

- Platform: **Linux x86_64**
- Build: run `make` in this directory (requires a C compiler like `gcc`/`clang` and standard build tooling such as `make`).

## Research / safety note

This is a **research project** intended to explore and evaluate large language model (LLM) capabilities.

The software in this release was generated with assistance from LLMs:
- Claude Opus 4.5
- GPT-5.2

using GitHub Copilot in VS Code.

Do not use this software in the expectation that it is **fit for any particular purpose**.

## License

The entire software in this release is provided under **CC0 1.0 Universal (Public Domain)**.
EOF
} >"$STAGE_ROOT/README.md"

# Copy only the needed sources.
mkdir -p "$STAGE_ROOT/compiler" "$STAGE_ROOT/core" "$STAGE_ROOT/tools"

# compiler/
cp -a "$ROOT_DIR/compiler"/*.c "$ROOT_DIR/compiler"/*.h "$STAGE_ROOT/compiler/"
# Optional linker script used by monacc when present.
if [ -f "$ROOT_DIR/compiler/minimal.ld" ]; then
	cp -a "$ROOT_DIR/compiler/minimal.ld" "$STAGE_ROOT/compiler/"
fi

# core/
cp -a "$ROOT_DIR/core"/*.c "$ROOT_DIR/core"/*.h "$STAGE_ROOT/core/"

# tools/
# Some repos may have only .c; tolerate missing .h.
cp -a "$ROOT_DIR/tools"/*.c "$STAGE_ROOT/tools/"
if ls "$ROOT_DIR/tools"/*.h >/dev/null 2>&1; then
	cp -a "$ROOT_DIR/tools"/*.h "$STAGE_ROOT/tools/"
fi

# Write a minimal Makefile for the tarball.
cat >"$STAGE_ROOT/Makefile" <<'EOF'
# monacc distro Makefile (minimal)

CC ?= cc
MONACC := bin/monacc

# Keep this minimal and distro-friendly.
CFLAGS_BASE := -Wall -Wextra -Wpedantic -fno-stack-protector -Os -DNDEBUG
CFLAGS := $(CFLAGS_BASE) -fno-pie
LDFLAGS := -s -Wl,--gc-sections -no-pie

START_LDFLAGS := -nostartfiles -Wl,-e,_start

# Core sources (keep aligned with the main repo Makefile).
CORE_MIN_SRC := \
	core/mc_str.c \
	core/mc_fmt.c \
	core/mc_snprint.c \
	core/mc_libc_compat.c \
	core/mc_start_env.c \
	core/mc_io.c \
	core/mc_regex.c

CORE_CRYPTO_SRC := \
	core/mc_sha256.c \
	core/mc_hmac.c \
	core/mc_hkdf.c \
	core/mc_aes.c \
	core/mc_gcm.c \
	core/mc_x25519.c

CORE_TLS_SRC := \
	core/mc_tls_record.c \
	core/mc_tls13.c \
	core/mc_tls13_transcript.c \
	core/mc_tls13_handshake.c

CORE_MATH_SRC := \
	core/mc_mathf.c

CORE_COMMON_SRC := $(CORE_MIN_SRC) $(CORE_CRYPTO_SRC) $(CORE_TLS_SRC) $(CORE_MATH_SRC)

# Tools build against the syscall-only core subset.
CORE_TOOL_SRC := $(CORE_COMMON_SRC)

# Compiler is a hosted binary, so it additionally needs the hosted entrypoint.
CORE_COMPILER_SRC := $(CORE_MIN_SRC) core/mc_start.c

COMPILER_SRC := \
	compiler/monacc_front.c \
	compiler/monacc_fmt.c \
	compiler/monacc_elfread.c \
	compiler/monacc_link.c \
	compiler/monacc_elfobj.c \
	compiler/monacc_sys.c \
	compiler/monacc_ast.c \
	compiler/monacc_parse.c \
	compiler/monacc_str.c \
	compiler/monacc_codegen.c \
	compiler/monacc_pp.c \
	compiler/monacc_main.c \
	$(CORE_COMPILER_SRC)

# Tools: build all tools/*.c with monacc and link internally.
TOOL_SRCS := $(wildcard tools/*.c)
TOOL_NAMES := $(basename $(notdir $(TOOL_SRCS)))
TOOL_BINS := $(addprefix bin/,$(TOOL_NAMES))

.PHONY: all clean

all: $(MONACC) $(TOOL_BINS) bin/realpath bin/[
	@echo ""
	@echo "Build complete: bin/monacc + $(words $(TOOL_BINS)) tools + aliases"

bin:
	mkdir -p bin

$(MONACC): $(COMPILER_SRC) | bin
	@echo "==> Building compiler"
	$(CC) $(CFLAGS) -I core -I compiler $(LDFLAGS) $(START_LDFLAGS) $(COMPILER_SRC) -o $@

bin/%: tools/%.c $(CORE_TOOL_SRC) $(MONACC) | bin
	@echo "  $*"
	@$(MONACC) -I core $< $(CORE_TOOL_SRC) -o $@

# Convenience aliases (match the main repo behavior).
bin/realpath: bin/readlink | bin
	@cp $< $@

bin/[: bin/test | bin
	@cp $< $@

clean:
	rm -rf bin
EOF

maybe_build_and_initramfs() {
	if [ "$WANT_INITRAMFS" != "1" ]; then
		return 0
	fi
	if ! command -v make >/dev/null 2>&1; then
		if [ "$INITRAMFS_STRICT" = "1" ]; then
			echo "error: make not found (required for initramfs build)" >&2
			exit 1
		fi
		echo "warning: make not found; skipping initramfs" >&2
		return 0
	fi
	if ! command -v cpio >/dev/null 2>&1; then
		if [ "$INITRAMFS_STRICT" = "1" ]; then
			echo "error: cpio not found (required to pack initramfs)" >&2
			exit 1
		fi
		echo "warning: cpio not found; skipping initramfs" >&2
		return 0
	fi
	if ! command -v gzip >/dev/null 2>&1; then
		if [ "$INITRAMFS_STRICT" = "1" ]; then
			echo "error: gzip not found (required to compress initramfs)" >&2
			exit 1
		fi
		echo "warning: gzip not found; skipping initramfs" >&2
		return 0
	fi

	JOBS=${DIST_JOBS:-4}
	echo "==> Building staged distro (for initramfs)" >&2
	make -C "$STAGE_ROOT" -j"$JOBS" all

	# Stage initramfs rootfs:
	# - /init is PID 1 (copied from bin/<name>)
	# - /bin contains all tools + monacc
	# - empty /dev,/proc,/sys mountpoints
	INIT_ROOT="$STAGE_BASE/initramfs-root"
	rm -rf "$INIT_ROOT"
	mkdir -p "$INIT_ROOT/bin" "$INIT_ROOT/dev" "$INIT_ROOT/proc" "$INIT_ROOT/sys"
	cp -a "$STAGE_ROOT/bin"/* "$INIT_ROOT/bin/"
	if [ -z "$INITRAMFS_INIT_NAME" ]; then
		echo "error: initramfs: --init=<name> must not be empty" >&2
		exit 1
	fi
	if [ ! -x "$INIT_ROOT/bin/$INITRAMFS_INIT_NAME" ]; then
		echo "error: initramfs: missing bin/$INITRAMFS_INIT_NAME" >&2
		exit 1
	fi
	cp -a "$INIT_ROOT/bin/$INITRAMFS_INIT_NAME" "$INIT_ROOT/init"

	# Pack initramfs (newc cpio) and gzip it.
	TMP_CPIO="$STAGE_BASE/monacc-$VERSION-initramfs.cpio"
	(
		cd "$INIT_ROOT"
		find . -print0 | LC_ALL=C sort -z | cpio --null -o --format=newc --owner=0:0 > "$TMP_CPIO"
	)
	cp -a "$TMP_CPIO" "$OUT_INITRAMFS_CPIO"
	gzip -n -9 -c "$TMP_CPIO" > "$OUT_INITRAMFS"
	rm -f "$TMP_CPIO"
	echo "Wrote $OUT_INITRAMFS_CPIO" >&2
	echo "Wrote $OUT_INITRAMFS" >&2
}

# Create tar.gz. Ensure the tarball contains only the staged directory.
# (Run from the stage base to avoid capturing absolute paths.)
(
	cd "$STAGE_BASE"
	tar czf "$OUT_TAR" "monacc-$VERSION"
)

echo "Wrote $OUT_TAR"

maybe_build_and_initramfs
