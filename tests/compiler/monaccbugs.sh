#!/usr/bin/env bash
set -euo pipefail

# Compiler regression suite for known bug fixes.
#
# This runs as part of `make test` by default.
# To skip locally (e.g. when iterating on a known-failing change), run:
#   SELFTEST_MONACCBUGS=0 make test

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

MONACC_BIN="${MONACC_BIN:-./bin/monacc}"

if [[ ! -x "$MONACC_BIN" ]]; then
  echo "monaccbugs: missing monacc binary at $MONACC_BIN" >&2
  echo "monaccbugs: run 'make' first" >&2
  exit 1
fi

out_dir="build/monaccbugs"
mkdir -p "$out_dir"

fail=0
ok=0

run_one() {
  local name="$1"
  shift
  local out_bin="$out_dir/$name"

  echo "  [build] $name"
  "$MONACC_BIN" "$@" -o "$out_bin" >/dev/null

  echo "  [run ] $name"
  set +e
  "$out_bin" >/dev/null 2>&1
  local rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then
    echo "  ok: $name"
    ok=$((ok + 1))
  else
    echo "  FAIL: $name (rc=$rc)"
    fail=$((fail + 1))
  fi
}

# P0/P1 bugfix tests (see docs/monaccbugs.md)
run_one sizeof-array tests/compiler/bugs/sizeof-array.c
run_one packed-offsetof tests/compiler/bugs/packed-offsetof.c
run_one packed-size tests/compiler/bugs/packed-size.c
run_one builtin-unreachable tests/compiler/bugs/builtin-unreachable.c
run_one compound-literal-assign tests/compiler/bugs/compound-literal-assign.c
run_one static-local-storage tests/compiler/bugs/static-local-storage.c
run_one extern-array-link tests/compiler/bugs/extern-array-use.c tests/compiler/bugs/extern-array-def.c
run_one extern-array-values tests/compiler/bugs/extern-array-values.c tests/compiler/bugs/extern-array-def.c

if [[ $fail -eq 0 ]]; then
  echo "monaccbugs: OK ($ok tests)"
  exit 0
fi

echo "monaccbugs: FAIL ($fail failing, $ok passing)"
exit 1
