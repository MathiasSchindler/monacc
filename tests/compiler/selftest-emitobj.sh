#!/usr/bin/env bash
set -euo pipefail

# Optional self-hosting probe using the internal ELF .o emitter (--emit-obj).
#
# This is intentionally not part of `make test` yet; use it as an additional
# regression check for the internal object writer under SELFHOST constraints.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

MONACC_BIN="${MONACC_BIN:-./bin/monacc}"

if [[ ! -x "$MONACC_BIN" ]]; then
  echo "selftest-emitobj: missing monacc binary at $MONACC_BIN" >&2
  echo "selftest-emitobj: run 'make' first" >&2
  exit 1
fi

out_dir="build/selftest-emitobj"
mkdir -p "$out_dir"

out_bin="$out_dir/monacc-self"
out_log="$out_dir/monacc-self.out"
err_log="$out_dir/monacc-self.err"
link_err="$out_dir/monacc-self.link.err"

# Keep the source list explicit and stable.
# Note: unlike scripts/selftest.sh, we include monacc_elfobj.c so the produced
# monacc-self also supports --emit-obj in SELFHOST mode.
src=(
  compiler/monacc_front.c
  compiler/monacc_fmt.c
  compiler/monacc_str.c
  compiler/monacc_sys.c
  compiler/monacc_ast.c
  compiler/monacc_parse.c
  compiler/monacc_codegen.c
  compiler/monacc_pp.c
  compiler/monacc_elfobj.c
  compiler/monacc_main.c

  # Core helpers used by the compiler.
  core/mc_str.c
  core/mc_snprint.c
  core/mc_start_env.c
)

selfhost_inc=(
  -I core
  -I compiler
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
  "$MONACC_BIN" --emit-obj "${selfhost_inc[@]}" -c "$f" -o "$o" 1>>"$out_log" 2>>"$err_log"
  ec=$?
  set -e
  if [[ $ec -ne 0 ]]; then
    compile_ec=$ec
    break
  fi
done

if [[ $compile_ec -ne 0 ]]; then
  first="$(head -n 1 "$err_log" | tr -d '\r')"
  echo "selftest-emitobj: compile: FAIL (exit: $compile_ec)"
  [[ -n "$first" ]] && echo "selftest-emitobj: first error: $first"
  echo "selftest-emitobj: logs: $err_log"
  exit $compile_ec
fi

echo "selftest-emitobj: compiled objects OK" >>"$out_log"

# Stage 2 (optional): link with host cc so the result is runnable.
if command -v cc >/dev/null 2>&1; then
  set +e
  cc -no-pie -O2 "${obj[@]}" -o "$out_bin" 1>>"$out_log" 2>"$link_err"
  link_ec=$?
  set -e
  if [[ $link_ec -ne 0 ]]; then
    first="$(head -n 1 "$link_err" | tr -d '\r')"
    echo "selftest-emitobj: compile: OK, link: FAIL (exit: $link_ec)"
    [[ -n "$first" ]] && echo "selftest-emitobj: first link error: $first"
    echo "selftest-emitobj: logs: $link_err"
    exit $link_ec
  fi

  echo "selftest-emitobj: compile: OK, link: OK"
  echo "selftest-emitobj: built $out_bin"

  # Follow-up: use the self-built compiler to build+run a few known examples.
  examples=(
    examples/hello.c
    examples/loop.c
    examples/pp.c
    examples/ptr.c
    examples/strlit.c
    examples/sizeof.c
    examples/struct.c
    examples/typedef.c
    examples/enum.c
    examples/asm_syscall.c
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
    echo "selftest-emitobj: run: OK (monacc-self built+ran $ok examples, expected rc=42)"
  else
    echo "selftest-emitobj: run: FAIL (monacc-self example check failed)"
    [[ -n "$first_msg" ]] && echo "selftest-emitobj: first error: $first_msg"
    exit 1
  fi

  exit 0
fi

echo "selftest-emitobj: compile: OK, link: SKIP (no host cc), run: SKIP"
echo "selftest-emitobj: logs: $out_log"
exit 0
