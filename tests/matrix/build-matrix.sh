#!/bin/sh
set -eu

# Build tools for multiple toolchains into bin/<tc>/
# Usage:
#   sh tests/matrix/build-matrix.sh [tc...]
# If no tc args are given, auto-detects monacc + gcc/clang versions.

. "$(dirname "$0")/common.sh"

ROOT="$(repo_root)"
cd "$ROOT"

fail=0

# Ensure baseline monacc build exists.
if [ ! -x ./bin/monacc ]; then
	say "matrix: missing ./bin/monacc (run: make)" >&2
	exit 1
fi

# Collect toolchains.
if [ "$#" -gt 0 ]; then
	TCS="$*"
else
	TCS="$(default_toolchains)"
fi

# Build flags for hosted compilers (gcc/clang) to stay libc-free and small.
# We use the same freestanding approach as sysbox: avoid libc/builtins and PIE.
HOST_CFLAGS="-Os -DNDEBUG -Wall -Wextra -Wpedantic -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -fno-pic -fno-pie -ffunction-sections -fdata-sections"
HOST_LDFLAGS="-nostdlib -nostartfiles -Wl,--gc-sections -Wl,-s -Wl,--build-id=none -Wl,-z,noseparate-code -Wl,-e,_start -no-pie"

# Core sources — keep in sync with CORE_COMMON_SRC in Makefile
CORE_COMMON="core/mc_str.c core/mc_fmt.c core/mc_snprint.c core/mc_libc_compat.c core/mc_start_env.c core/mc_io.c core/mc_regex.c core/mc_sha256.c core/mc_hmac.c core/mc_hkdf.c core/mc_tls13.c core/mc_tls13_transcript.c core/mc_tls13_handshake.c core/mc_aes.c core/mc_gcm.c core/mc_x25519.c core/mc_tls_record.c"
CORE_START="core/mc_start.c"

OUT_BASE="build/matrix"
mkdir -p "$OUT_BASE"

# Record build modes (static/dynamic) per tool into a TSV.
BUILD_TSV="$OUT_BASE/build.tsv"
: >"$BUILD_TSV"

# Iterate tool source files.
# shellcheck disable=SC2045
TOOLS="$(ls tools/*.c 2>/dev/null || true)"
if [ -z "$TOOLS" ]; then
	die "no tools found under tools/"
fi

for tc in $TCS; do
	TC_DIR="$(tc_dirname "$tc")"
	CC_CMD="$(compiler_for_tc "$tc")"
	if [ -z "$CC_CMD" ]; then
		say "matrix: skip unknown tc: $tc" >&2
		continue
	fi
	if ! have_cmd "${CC_CMD#./}" && ! have_cmd "$CC_CMD"; then
		# For ./bin/monacc, have_cmd won't work; check file exists.
		if [ "$CC_CMD" != "./bin/monacc" ]; then
			say "matrix: skip missing compiler: $CC_CMD" >&2
			continue
		fi
	fi

	OUT_BIN="bin/$TC_DIR"
	# Avoid stale binaries masking build failures.
	rm -rf "$OUT_BIN"
	mkdir -p "$OUT_BIN"

	tc_fail=0

	say "matrix: building tc=$tc -> $OUT_BIN"

	for src in $TOOLS; do
		tool="$(basename "$src" .c)"
		out="$OUT_BIN/$tool"

		mode=""
		if [ "$tc" = "monacc" ]; then
			# Build with monacc similarly to the main Makefile.
			if ./bin/monacc -I core "$src" $CORE_COMMON -o "$out" >/dev/null 2>"$OUT_BASE/${TC_DIR}-${tool}.err"; then
				mode="monacc"
			else
				say "matrix: FAIL tc=$tc tool=$tool (see $OUT_BASE/${TC_DIR}-${tool}.err)" >&2
				tc_fail=1
				fail=1
				printf '%s\t%s\t%s\t%s\n' "$tc" "$tool" "FAIL" "" >>"$BUILD_TSV"
				continue
			fi
		else
			# Hosted compiler: try static first, then fall back to non-static.
			err="$OUT_BASE/${TC_DIR}-${tool}.err"
			if "$CC_CMD" $HOST_CFLAGS -I core $CORE_START $CORE_COMMON "$src" $HOST_LDFLAGS -static -o "$out" >"$OUT_BASE/${TC_DIR}-${tool}.out" 2>"$err"; then
				mode="static"
			elif "$CC_CMD" $HOST_CFLAGS -I core $CORE_START $CORE_COMMON "$src" $HOST_LDFLAGS -o "$out" >"$OUT_BASE/${TC_DIR}-${tool}.out" 2>"$err"; then
				mode="dynamic"
			else
				say "matrix: FAIL tc=$tc tool=$tool (see $err)" >&2
				tc_fail=1
				fail=1
				printf '%s\t%s\t%s\t%s\n' "$tc" "$tool" "FAIL" "" >>"$BUILD_TSV"
				continue
			fi
		fi

		# Record size.
		bytes="0"
		if [ -f "$out" ]; then
			bytes="$(wc -c <"$out" | tr -d ' ')"
		fi
		printf '%s\t%s\t%s\t%s\t%s\n' "$tc" "$tool" "OK" "$mode" "$bytes" >>"$BUILD_TSV"
	done

	# Aliases (match top-level build): realpath <- readlink, [ <- test.
	if [ -f "$OUT_BIN/readlink" ]; then
		cp "$OUT_BIN/readlink" "$OUT_BIN/realpath" 2>/dev/null || true
	fi
	if [ -f "$OUT_BIN/test" ]; then
		cp "$OUT_BIN/test" "$OUT_BIN/[" 2>/dev/null || true
	fi

	if [ "$tc_fail" -ne 0 ]; then
		say "matrix: FAIL tc=$tc" >&2
	fi

done

say "matrix: build report: $BUILD_TSV"

if [ "$fail" -ne 0 ]; then
	exit 1
fi
