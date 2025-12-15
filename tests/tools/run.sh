#!/bin/sh
set -eu

# TEST_DIR is where this script lives (tests/tools/)
TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# ROOT_DIR is the project root (tests/tools/../..)
ROOT_DIR=$(CDPATH= cd -- "$TEST_DIR/../.." && pwd)
BIN=${SB_TEST_BIN:-"$ROOT_DIR/bin"}
DATA_DIR="$TEST_DIR/data"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

DBG=${SB_TEST_DEBUG:-0}
mark() {
  [ "$DBG" = "1" ] && echo "MARK: $*" >&2
  return 0
}

# Create a private temp dir for each run
TMP=${TMPDIR:-/tmp}/sysbox-tests-$$
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM
mkdir -p "$TMP"

# Suites to run (space-separated). Default is everything.
# - If args are provided, they override the default.
# - SB_TEST_SUITES overrides everything (useful for CI).
if [ $# -gt 0 ]; then
  case "$1" in
    -h|--help)
      echo "usage: tests/run.sh [smoke] [integration] [realworld]" >&2
      echo "env: SB_TEST_SUITES='...' SB_TEST_SHOW_SUITES=1 SB_TEST_DEBUG=1" >&2
      exit 2
      ;;
  esac
  SUITES="$*"
else
  SUITES="smoke integration realworld"
fi

SUITES=${SB_TEST_SUITES:-"$SUITES"}

run_suite() {
  # $1 suite_name, $2 suite_script, then args
  NAME=$1
  SCRIPT=$2
  shift 2

  case " $SUITES " in
    (*" $NAME "*) : ;;
    (*)
      if [ "$NAME" = "integration" ] || [ "$NAME" = "realworld" ]; then
        printf '%s' "0"
        return 0
      fi
      printf '%s' "skipped"
      return 0
      ;;
  esac

  mark "$NAME"

  if [ "$NAME" = "integration" ] || [ "$NAME" = "realworld" ]; then
    # Suites that support SB_TEST_COUNT
    CHECKS=$(SB_TEST_COUNT=1 sh "$SCRIPT" "$@") || fail "$NAME suite failed"
    printf '%s' "$CHECKS"
    return 0
  fi

  sh "$SCRIPT" "$@" || fail "$NAME suite failed"
  printf '%s' "ok"
  return 0
}

mark "setup"
sh "$TEST_DIR/suites/require_bins.sh" "$BIN" || fail "missing required binaries (build first)"

SMOKE_STATUS=$(run_suite smoke "$TEST_DIR/suites/smoke.sh" "$BIN" "$TMP")
INTEGRATION_CHECKS=$(run_suite integration "$TEST_DIR/suites/integration.sh" "$BIN" "$TMP")
RECIPES_CHECKS=$(run_suite realworld "$TEST_DIR/suites/realworld.sh" "$BIN" "$TMP" "$DATA_DIR")

if [ "${SB_TEST_SHOW_SUITES:-0}" = "1" ]; then
  echo "OK (smoke=$SMOKE_STATUS, integration=${INTEGRATION_CHECKS} checks, recipes=${RECIPES_CHECKS} checks, tmp=$TMP)"
else
  echo "OK (integration=${INTEGRATION_CHECKS} checks, recipes=${RECIPES_CHECKS} checks, tmp=$TMP)"
fi