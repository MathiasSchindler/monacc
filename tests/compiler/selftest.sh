#!/usr/bin/env bash
set -euo pipefail

# Non-blocking self-hosting probe.
#
# Attempts to compile monacc using the host-built ./monacc.
# This is informational by default: it always exits 0, but writes logs.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MONACC_BIN="${MONACC_BIN:-./monacc}"

if [[ ! -x "$MONACC_BIN" ]]; then
  echo "selftest: missing monacc binary at $MONACC_BIN" >&2
  echo "selftest: run 'make all' first" >&2
  exit 0
fi

out_dir="build/selftest"
mkdir -p "$out_dir"

out_bin="$out_dir/monacc-self"
out_log="$out_dir/monacc-self.out"
err_log="$out_dir/monacc-self.err"
link_err="$out_dir/monacc-self.link.err"

# Keep the source list explicit and stable.
# (This matches the main Makefile build list.)
src=(
  src/monacc_front.c
  src/monacc_fmt.c
  src/monacc_str.c
  src/monacc_sys.c
  src/monacc_ast.c
  src/monacc_parse.c
  src/monacc_codegen.c
  src/monacc_pp.c
  src/monacc_main.c
)

selfhost_inc=(
  -I selfhost/include
  -DSELFHOST
)

: >"$out_log"
: >"$err_log"
: >"$link_err"

obj=()

# Stage 1: compile+assemble each file to a .o (no linking, no _start).
compile_ec=0
for f in "${src[@]}"; do
  o="$out_dir/$(basename "$f" .c).o"
  obj+=("$o")
  set +e
  "$MONACC_BIN" "${selfhost_inc[@]}" -c "$f" -o "$o" 1>>"$out_log" 2>>"$err_log"
  ec=$?
  set -e
  if [[ $ec -ne 0 ]]; then
    compile_ec=$ec
    break
  fi
done

if [[ $compile_ec -ne 0 ]]; then
  first="$(head -n 1 "$err_log" | tr -d '\r')"
  echo "selftest: compile: FAIL (exit: $compile_ec)"
  [[ -n "$first" ]] && echo "selftest: first error: $first"
  echo "selftest: logs: $err_log"
  exit 0
fi

echo "selftest: compiled objects OK" >>"$out_log"

# Stage 2 (optional): link with host cc so the result is runnable.
if command -v cc >/dev/null 2>&1; then
  set +e
  cc -no-pie -O2 "${obj[@]}" -o "$out_bin" 1>>"$out_log" 2>"$link_err"
  link_ec=$?
  set -e
  if [[ $link_ec -ne 0 ]]; then
    first="$(head -n 1 "$link_err" | tr -d '\r')"
    echo "selftest: compile: OK, link: FAIL (exit: $link_ec)"
    [[ -n "$first" ]] && echo "selftest: first link error: $first"
    echo "selftest: logs: $link_err"
    exit 0
  fi

  echo "selftest: compile: OK, link: OK"
  echo "selftest: built $out_bin"

  # Follow-up: use the self-built compiler to build+run a few known examples.
  # Still informational: failures are logged but do not fail make test.
  examples=(
    examples/hello.c
    examples/loop.c
    examples/pp.c
    examples/ptr.c
    examples/strlit.c
  )

  ok=0
  fail=0
  first_msg=""

  for ex in "${examples[@]}"; do
    base="$(basename "$ex" .c)"
    ex_out="$out_dir/${base}-self"
    ex_err="$out_dir/${base}-self.err"
    : >"$ex_err"

    set +e
    (
      "$out_bin" "$ex" -o "$ex_out" 1>/dev/null 2>"$ex_err"
    )
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
    echo "selftest: run: OK (monacc-self built+ran $ok examples, expected rc=42)"
  else
    echo "selftest: run: FAIL (monacc-self example check failed)"
    [[ -n "$first_msg" ]] && echo "selftest: first error: $first_msg"
  fi

  exit 0
fi

echo "selftest: compile: OK, link: SKIP (no host cc), run: SKIP"
echo "selftest: logs: $out_log"
exit 0
