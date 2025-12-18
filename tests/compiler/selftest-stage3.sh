#!/usr/bin/env bash
set -euo pipefail

# Opt-in stage-3 self-hosting probe.
#
# Builds a stage-3 compiler using bin/monacc-self2, then tries to compile+run a
# small set of examples using the stage-3 compiler.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

STRICT=0
if [[ "${SELFTEST_STAGE3_STRICT:-0}" == "1" ]]; then
  STRICT=1
fi

MONACC_BIN="${MONACC_BIN:-./bin/monacc}"
MONACC_SELF="${MONACC_SELF:-./bin/monacc-self}"
MONACC_SELF2="${MONACC_SELF2:-./bin/monacc-self2}"

if [[ ! -x "$MONACC_BIN" ]]; then
  echo "selftest-stage3: missing monacc binary at $MONACC_BIN" >&2
  echo "selftest-stage3: run 'make' first" >&2
  if [[ $STRICT -eq 1 ]]; then exit 1; fi
  exit 0
fi

# Ensure stage-2 exists (stage-3 builds from it).
if [[ ! -x "$MONACC_SELF2" ]]; then
  if [[ ! -x "$MONACC_SELF" ]]; then
    echo "selftest-stage3: missing monacc-self at $MONACC_SELF" >&2
    echo "selftest-stage3: run 'make selfhost' first" >&2
    if [[ $STRICT -eq 1 ]]; then
      set +e
      make selfhost MONACC_BIN="$MONACC_BIN" 1>/dev/null
      mk_ec=$?
      set -e
      if [[ $mk_ec -ne 0 ]] || [[ ! -x "$MONACC_SELF" ]]; then
        echo "selftest-stage3: build selfhost: FAIL" >&2
        exit 1
      fi
    else
      exit 0
    fi
  fi

  out_dir="build/selftest-stage3"
  mkdir -p "$out_dir"
  out_log="$out_dir/stage2.out"
  err_log="$out_dir/stage2.err"
  : >"$out_log"
  : >"$err_log"

  set +e
  make selfhost2 MONACC_SELF="$MONACC_SELF" 1>>"$out_log" 2>>"$err_log"
  mk_ec=$?
  set -e

  if [[ $mk_ec -ne 0 ]]; then
    echo "selftest-stage3: build stage2: FAIL (exit: $mk_ec)"
    first="$(head -n 1 "$err_log" | tr -d '\r')"
    [[ -n "$first" ]] && echo "selftest-stage3: first error: $first"
    echo "selftest-stage3: logs: $err_log"
    if [[ $STRICT -eq 1 ]]; then exit 1; fi
    exit 0
  fi

  MONACC_SELF2=./bin/monacc-self2
fi

out_dir="build/selftest-stage3"
mkdir -p "$out_dir"

out_bin="$out_dir/monacc-self3"
out_log="$out_dir/stage3.out"
err_log="$out_dir/stage3.err"

: >"$out_log"
: >"$err_log"

set +e
make selfhost3 MONACC_SELF2="$MONACC_SELF2" 1>>"$out_log" 2>>"$err_log"
mk_ec=$?
set -e

if [[ $mk_ec -ne 0 ]]; then
  echo "selftest-stage3: build: FAIL (exit: $mk_ec)"
  first="$(head -n 1 "$err_log" | tr -d '\r')"
  [[ -n "$first" ]] && echo "selftest-stage3: first error: $first"
  echo "selftest-stage3: logs: $err_log"
  if [[ $STRICT -eq 1 ]]; then exit 1; fi
  exit 0
fi

if [[ -x ./bin/monacc-self3 ]]; then
  cp ./bin/monacc-self3 "$out_bin" 2>>"$err_log" || true
else
  echo "selftest-stage3: build succeeded but ./bin/monacc-self3 missing" >&2
  exit 0
fi

echo "selftest-stage3: built $out_bin"

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
  ex_out="$out_dir/${base}-stage3"
  ex_err="$out_dir/${base}-stage3.err"
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
  echo "selftest-stage3: run: OK (stage3 built+ran $ok examples, expected rc=42)"
else
  echo "selftest-stage3: run: FAIL (stage3 example check failed)"
  [[ -n "$first_msg" ]] && echo "selftest-stage3: first error: $first_msg"
  if [[ $STRICT -eq 1 ]]; then exit 1; fi
fi

exit 0
