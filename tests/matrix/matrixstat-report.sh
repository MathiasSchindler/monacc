#!/bin/sh
set -eu

# Emit a TSV matrixstat report for bin/<tc_dir>/*
# Usage:
#   sh tests/matrix/matrixstat-report.sh [tc...]
# If no args, uses the same default set as build-matrix.sh.
# Override defaults via MATRIX_TCS (space-separated), e.g.:
#   MATRIX_TCS="monacc gcc-15 clang-21" sh tests/matrix/matrixstat-report.sh
#
# Output:
#   build/matrix/matrixstat.tsv
#
# Notes:
# - This runs ./bin/matrixstat once per compiler dir (so it only reports the
#   toolchains selected for this matrix run, even if older bin/*_*/ dirs exist).

. "$(dirname "$0")/common.sh"

ROOT="$(repo_root)"
cd "$ROOT"

if [ "$#" -gt 0 ]; then
	TCS="$*"
else
	TCS="$(default_toolchains)"
fi

if [ ! -x ./bin/matrixstat ]; then
	die "matrixstat-report: missing ./bin/matrixstat (run: make)"
fi

OUT_DIR="build/matrix"
OUT_TSV="$OUT_DIR/matrixstat.tsv"
mkdir -p "$OUT_DIR"

# Default to per-tool output (includes __TOTAL__ rows too).
ARGS="--per-tool"
if [ -n "${MATRIXSTAT_ARGS:-}" ]; then
	# Advanced escape hatch.
	ARGS="$MATRIXSTAT_ARGS"
fi

first=1
for tc in $TCS; do
	TC_DIR="$(tc_dirname "$tc")"
	BIN="bin/$TC_DIR"
	if [ ! -d "$BIN" ]; then
		continue
	fi
	if [ "$first" -eq 1 ]; then
		./bin/matrixstat $ARGS --only "$TC_DIR" >"$OUT_TSV"
		first=0
	else
		./bin/matrixstat $ARGS --only "$TC_DIR" | sed '1d' >>"$OUT_TSV"
	fi

done

# If nothing was written (no toolchains found), emit only a header.
if [ "$first" -eq 1 ]; then
	./bin/matrixstat $ARGS --only monacc_ 2>/dev/null | head -n 1 >"$OUT_TSV" || true
fi
