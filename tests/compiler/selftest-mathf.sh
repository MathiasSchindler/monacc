#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

MONACC_BIN="${MONACC_BIN:-./bin/monacc}"

if [[ ! -x "$MONACC_BIN" ]]; then
  echo "selftest-mathf: missing monacc binary at $MONACC_BIN" >&2
  echo "selftest-mathf: run 'make' first" >&2
  exit 1
fi

out_dir="build/selftest-mathf"
mkdir -p "$out_dir"

core_src=(
  core/mc_str.c
  core/mc_fmt.c
  core/mc_snprint.c
  core/mc_libc_compat.c
  core/mc_start_env.c
  core/mc_io.c
  core/mc_regex.c
  core/mc_mathf.c
)

build_and_run() {
  local name="$1"
  local src="$2"
  local out="$out_dir/$name"
  local err="$out_dir/$name.err"

  : >"$err"

  "$MONACC_BIN" --emit-obj --link-internal -I core "$src" "${core_src[@]}" -o "$out" 1>/dev/null 2>"$err"

  set +e
  "$out" 1>/dev/null 2>>"$err"
  local rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    first="$(head -n 1 "$err" | tr -d '\r')"
    echo "selftest-mathf: FAIL ($name: rc=$rc)${first:+: $first}" >&2
    echo "selftest-mathf: log: $err" >&2
    return 1
  fi

  echo "selftest-mathf: OK ($name)"
}

build_and_run "mc_mathf_test" "tests/compiler/mc_mathf_test.c"
build_and_run "mc_tensor_f32_test" "tests/compiler/mc_tensor_f32_test.c"

# Optional: regression check for v3 q8 padding. Disabled by default because it
# requires a local model file.
#
# Usage:
#   GPT2_V3_Q8_MODEL=/path/to/gpt2_q8.bin make test
if [[ -n "${GPT2_V3_Q8_MODEL:-}" ]]; then
  if [[ ! -f "$GPT2_V3_Q8_MODEL" ]]; then
    echo "selftest-mathf: GPT2_V3_Q8_MODEL points to missing file: $GPT2_V3_Q8_MODEL" >&2
    exit 1
  fi

  name="gpt2_v3_padding_test"
  out="$out_dir/$name"
  err="$out_dir/$name.err"
  : >"$err"

  "$MONACC_BIN" --emit-obj --link-internal -I core "tests/compiler/gpt2_v3_padding_test.c" "${core_src[@]}" -o "$out" 1>/dev/null 2>"$err"

  set +e
  "$out" "$GPT2_V3_Q8_MODEL" 1>/dev/null 2>>"$err"
  rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    first="$(head -n 1 "$err" | tr -d '\r')"
    echo "selftest-mathf: FAIL ($name: rc=$rc)${first:+: $first}" >&2
    echo "selftest-mathf: log: $err" >&2
    exit 1
  fi

  echo "selftest-mathf: OK ($name)"
else
  echo "selftest-mathf: SKIP (set GPT2_V3_Q8_MODEL to run v3 padding check)"
fi
