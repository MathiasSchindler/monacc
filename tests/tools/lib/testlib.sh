#!/bin/sh

# Shared helpers for sysbox test suites.
# This file is meant to be sourced by other test scripts.

set -eu

: "${SB_TEST_VERBOSE:=0}"
: "${SB_TEST_COUNT:=0}"
: "${SB_TEST_DEBUG:=0}"

VERBOSE=$SB_TEST_VERBOSE
COUNT_ONLY=$SB_TEST_COUNT
DBG=$SB_TEST_DEBUG

LAST_CMD=""
CHECKS=${CHECKS:-0}

vlog() {
  [ "$VERBOSE" = "1" ] && echo "$*" >&2
  return 0
}

mark() {
  [ "$DBG" = "1" ] && echo "MARK: $*" >&2
  return 0
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

fail_cmp() {
  # $1 desc, $2 expected, $3 actual
  echo "FAIL: $1" >&2
  if [ "$VERBOSE" = "1" ]; then
    [ -n "$LAST_CMD" ] && echo "  cmd:      $LAST_CMD" >&2
    echo "  expected: '$2'" >&2
    echo "  actual:   '$3'" >&2
  fi
  exit 1
}

assert_eq() {
  # $1 desc, $2 expected, $3 actual
  [ "$2" = "$3" ] || fail_cmp "$1" "$2" "$3"
  CHECKS=$((CHECKS + 1))
  vlog "PASS: $1"
}

assert_nonempty() {
  # $1 desc, $2 actual
  [ -n "$2" ] || fail_cmp "$1" "<non-empty>" "$2"
  CHECKS=$((CHECKS + 1))
  vlog "PASS: $1"
}

assert_rc() {
  # $1 desc, $2 expected_rc, $3 actual_rc
  if [ "$2" -ne "$3" ]; then
    if [ "$VERBOSE" = "1" ]; then
      echo "FAIL: $1" >&2
      [ -n "$LAST_CMD" ] && echo "  cmd:        $LAST_CMD" >&2
      echo "  expected rc: $2" >&2
      echo "  actual rc:   $3" >&2
    else
      echo "FAIL: $1 (expected rc $2, got $3)" >&2
    fi
    exit 1
  fi
  CHECKS=$((CHECKS + 1))
  vlog "PASS: $1"
}

# Sysbox-only command execution helpers.
# Expect BIN to point at the sysbox bin/ directory.

run_box() {
  # $1: command string for sysbox sh -c
  : "${BIN:?run_box requires BIN=/path/to/sysbox/bin}"
  LAST_CMD=$1
  vlog "RUN: $1"
  "$BIN/env" -i PATH="$BIN" "$BIN/sh" -c "$1"
}

run_box_argv() {
  # $1: command string for sysbox sh -c, then extra argv
  : "${BIN:?run_box_argv requires BIN=/path/to/sysbox/bin}"
  CMD=$1
  shift
  LAST_CMD="$BIN/sh -c $CMD $*"
  vlog "RUN: $BIN/sh -c $CMD $*"
  "$BIN/env" -i PATH="$BIN" "$BIN/sh" -c "$CMD" "$@"
}

run_script() {
  # Usage: run_script SCRIPT [args...]
  : "${BIN:?run_script requires BIN=/path/to/sysbox/bin}"
  LAST_CMD="$BIN/sh $*"
  vlog "RUN: $BIN/sh $*"
  "$BIN/env" -i PATH="$BIN" "$BIN/sh" "$@"
}

run_box_rc() {
  # echoes stdout to caller via command substitution; sets RC via global
  # shellcheck disable=SC2034
  RC=0
  set +e
  OUT=$(run_box "$1")
  RC=$?
  set -e
  printf '%s' "$OUT"
  return 0
}
