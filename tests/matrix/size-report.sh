#!/bin/sh
set -eu

# Emit a TSV size report for bin/<tc>/*
# Usage:
#   ./bin/sh tests/matrix/size-report.sh [tc...]

. "$(dirname "$0")/common.sh"

ROOT="$(repo_root)"
cd "$ROOT"

if [ "$#" -gt 0 ]; then
	TCS="$*"
else
	TCS="$(default_toolchains)"
fi

printf 'toolchain\ttool\tbytes\n'

for tc in $TCS; do
	TC_DIR="$(tc_dirname "$tc")"
	BIN="bin/$TC_DIR"
	if [ ! -d "$BIN" ]; then
		continue
	fi
	for f in "$BIN"/*; do
		[ -f "$f" ] || continue
		[ -x "$f" ] || continue
		tool="$(basename "$f")"
		bytes="$(wc -c <"$f" | tr -d ' ')"
		printf '%s\t%s\t%s\n' "$tc" "$tool" "$bytes"
	done

done
