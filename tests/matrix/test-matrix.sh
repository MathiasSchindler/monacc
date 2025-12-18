#!/bin/sh
set -eu

# Smoke-test tool binaries under bin/<tc>/
# Usage:
#   sh tests/matrix/test-matrix.sh [tc...]
# If no args, auto-detects the same set as build-matrix.sh.

. "$(dirname "$0")/common.sh"

ROOT="$(repo_root)"
cd "$ROOT"

if [ "$#" -gt 0 ]; then
	TCS="$*"
else
	TCS="$(default_toolchains)"
fi

fail=0

smoke_one_tc() {
	tc="$1"
	TC_DIR="$(tc_dirname "$tc")"
	BIN="bin/$TC_DIR"

	if [ ! -d "$BIN" ]; then
		say "matrix: SKIP tc=$tc (missing $BIN)" >&2
		return 2
	fi
	if [ ! -x "$BIN/sh" ]; then
		say "matrix: SKIP tc=$tc (missing $BIN/sh)" >&2
		return 2
	fi

	say "matrix: testing tc=$tc"

	# Basic sanity: echo/cat/true/false.
	"$BIN/echo" ok >/dev/null 2>/dev/null || return 1
	"$BIN/true" >/dev/null 2>/dev/null || return 1
	"$BIN/false" >/dev/null 2>/dev/null && return 1

	# sh -c basic
	"$BIN/sh" -c 'echo ok' >/dev/null 2>/dev/null || return 1

	# grep/sed/wc with a pipe (supported by our sh).
	"$BIN/sh" -c 'printf "a\nb\n" | grep b | sed s/b/x/ | wc -l' >/dev/null 2>/dev/null || return 1

	# test builtin tool (named "test" or "[")
	if [ -x "$BIN/test" ]; then
		"$BIN/test" 1 = 1 || return 1
	elif [ -x "$BIN/[" ]; then
		"$BIN/[" 1 = 1 ] || return 1
	fi

	# ls runs (don’t validate output; just ensure it doesn’t crash)
	"$BIN/ls" "$BIN" >/dev/null 2>/dev/null || return 1

	return 0
}

for tc in $TCS; do
	# Under `set -e`, a non-zero return would abort the script.
	# Run via `if` so we can treat "missing" as a normal SKIP.
	if smoke_one_tc "$tc"; then
		rc=0
	else
		rc=$?
	fi
	if [ "$rc" -eq 0 ]; then
		say "matrix: OK tc=$tc"
	elif [ "$rc" -eq 2 ]; then
		say "matrix: SKIP tc=$tc"
	else
		say "matrix: FAIL tc=$tc" >&2
		fail=1
	fi

done

if [ "$fail" -ne 0 ]; then
	exit 1
fi

say "matrix: all selected toolchains OK"
