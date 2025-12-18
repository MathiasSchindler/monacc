#!/usr/bin/env bash
set -euo pipefail

# Non-blocking stage-2 self-hosting probe.
#
# Builds a stage-2 compiler using bin/monacc-self, then tries to compile+run a
# small set of examples using the stage-2 compiler.
#
# This is informational by default: it always exits 0, but writes logs.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

STRICT=0
if [[ "${SELFTEST_STAGE2_STRICT:-0}" == "1" ]]; then
  STRICT=1
fi

INTERNAL=0
if [[ "${SELFTEST_STAGE2_INTERNAL:-0}" == "1" ]]; then
  INTERNAL=1
fi

# Allow caller overrides.
MONACC_BIN="${MONACC_BIN:-./bin/monacc}"
MONACC_SELF="${MONACC_SELF:-./bin/monacc-self}"

if [[ ! -x "$MONACC_BIN" ]]; then
  echo "selftest-stage2: missing monacc binary at $MONACC_BIN" >&2
  echo "selftest-stage2: run 'make' first" >&2
  exit 0
fi

if [[ ! -x "$MONACC_SELF" ]]; then
  echo "selftest-stage2: missing monacc-self binary at $MONACC_SELF" >&2
  echo "selftest-stage2: run 'make selfhost' first" >&2
  exit 0
fi

out_dir="build/selftest-stage2"
mkdir -p "$out_dir"

out_bin="$out_dir/monacc-self2"
out_log="$out_dir/stage2.out"
err_log="$out_dir/stage2.err"

: >"$out_log"
: >"$err_log"

# Build stage-2 using Makefile rules so it stays in sync with source lists.
set +e
make selfhost2 MONACC_SELF="$MONACC_SELF" 1>>"$out_log" 2>>"$err_log"
mk_ec=$?
set -e

if [[ $mk_ec -ne 0 ]]; then
  echo "selftest-stage2: build: FAIL (exit: $mk_ec)"
  first="$(head -n 1 "$err_log" | tr -d '\r')"
  [[ -n "$first" ]] && echo "selftest-stage2: first error: $first"
  echo "selftest-stage2: logs: $err_log"
  if [[ $STRICT -eq 1 ]]; then exit 1; fi
  exit 0
fi

# Copy the built binary into our out_dir with a stable name.
if [[ -x ./bin/monacc-self2 ]]; then
  cp ./bin/monacc-self2 "$out_bin" 2>>"$err_log" || true
else
  echo "selftest-stage2: build succeeded but ./bin/monacc-self2 missing" >&2
  exit 0
fi

echo "selftest-stage2: built $out_bin"

examples=(
  examples/hello.c
  examples/cmp_signed0.c
  examples/loop.c
  examples/pp.c
  examples/ptr.c
  examples/strlit.c
  examples/sizeof.c
  examples/struct.c
  examples/asm_syscall.c
)

ok=0
fail=0
first_msg=""

for ex in "${examples[@]}"; do
  base="$(basename "$ex" .c)"
  ex_out="$out_dir/${base}-stage2"
  ex_err="$out_dir/${base}-stage2.err"
  : >"$ex_err"

  set +e
  ( "$out_bin" "$ex" -o "$ex_out" 1>/dev/null 2>"$ex_err" )
  ex_ec=$?
  set -e

  if [[ $ex_ec -ne 0 ]]; then
    fail=1
    if [[ -z "$first_msg" ]]; then
      first="$(head -n 1 "$ex_err" | tr -d '\r')"
      if [[ $ex_ec -ge 128 ]]; then
        first_msg="compile $ex: crash (exit $ex_ec)${first:+: $first}"
      else
        first_msg="compile $ex: ${first:-exit $ex_ec}"
      fi
    fi
    break
  fi

  set +e
  "$ex_out" >/dev/null
  rc=$?
  set -e

  if [[ $rc -ne 42 ]]; then
    fail=1
    if [[ -z "$first_msg" ]]; then
      first_msg="run $ex_out: rc=$rc (expected 42)"
    fi
    break
  fi

  ok=$((ok + 1))
done

if [[ $fail -eq 0 ]]; then
  echo "selftest-stage2: run: OK (stage2 built+ran $ok examples, expected rc=42)"
else
  echo "selftest-stage2: run: FAIL (stage2 example check failed)"
  [[ -n "$first_msg" ]] && echo "selftest-stage2: first error: $first_msg"
  if [[ $STRICT -eq 1 ]]; then exit 1; fi
fi

if [[ $INTERNAL -eq 1 ]]; then
  ok=0
  fail=0
  first_msg=""

  for ex in "${examples[@]}"; do
    base="$(basename "$ex" .c)"
    ex_out="$out_dir/${base}-stage2-internal"
    ex_err="$out_dir/${base}-stage2-internal.err"
    : >"$ex_err"

    set +e
    ( "$out_bin" --emit-obj --link-internal "$ex" -o "$ex_out" 1>/dev/null 2>"$ex_err" )
    ex_ec=$?
    set -e

    if [[ $ex_ec -ne 0 ]]; then
      fail=1
      if [[ -z "$first_msg" ]]; then
        first="$(head -n 1 "$ex_err" | tr -d '\r')"
        if [[ $ex_ec -ge 128 ]]; then
          first_msg="compile(internal) $ex: crash (exit $ex_ec)${first:+: $first}"
        else
          first_msg="compile(internal) $ex: ${first:-exit $ex_ec}"
        fi
      fi
      break
    fi

    set +e
    "$ex_out" >/dev/null
    rc=$?
    set -e

    if [[ $rc -ne 42 ]]; then
      fail=1
      if [[ -z "$first_msg" ]]; then
        first_msg="run $ex_out: rc=$rc (expected 42)"
      fi
      break
    fi

    ok=$((ok + 1))
  done

  if [[ $fail -eq 0 ]]; then
    echo "selftest-stage2: internal: OK (stage2 built+ran $ok examples, expected rc=42)"
  else
    echo "selftest-stage2: internal: FAIL (stage2 internal example check failed)"
    [[ -n "$first_msg" ]] && echo "selftest-stage2: first error: $first_msg"
    if [[ $STRICT -eq 1 ]]; then exit 1; fi
  fi
fi

exit 0
