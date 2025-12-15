#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MONACC_BIN="${MONACC_BIN:-./monacc}"

mkdir -p build

if [[ ! -x "$MONACC_BIN" ]]; then
  echo "cli-smoke: missing monacc binary at $MONACC_BIN" >&2
  exit 1
fi

# 1) --dump-pp should write a non-empty file.
dump_pp="build/cli-smoke.pp"
rm -f "$dump_pp"
"$MONACC_BIN" --dump-pp "$dump_pp" examples/pp.c -o build/cli-smoke-pp
[[ -s "$dump_pp" ]]
# Basic sanity: preprocessed output should contain a main.
grep -q "int main" "$dump_pp"

# 2) Toolchain selection should work.
AS_PATH="$(command -v as)"
LD_PATH="$(command -v ld)"
AS_DIR="$(dirname "$AS_PATH")"
LD_DIR="$(dirname "$LD_PATH")"

"$MONACC_BIN" --as "$AS_PATH" --ld "$LD_PATH" examples/hello.c -o build/cli-smoke-asld
set +e
./build/cli-smoke-asld >/dev/null
rc=$?
set -e
[[ $rc -eq 42 ]]

if [[ "$AS_DIR" == "$LD_DIR" ]]; then
  "$MONACC_BIN" --toolchain "$AS_DIR" examples/hello.c -o build/cli-smoke-toolchain
  set +e
  ./build/cli-smoke-toolchain >/dev/null
  rc=$?
  set -e
  [[ $rc -eq 42 ]]
fi

# 3) Internal .o emission should work (skips external 'as').
"$MONACC_BIN" --emit-obj examples/hello.c -o build/cli-smoke-emit-obj
set +e
./build/cli-smoke-emit-obj >/dev/null
rc=$?
set -e
[[ $rc -eq 42 ]]

echo "cli-smoke: OK"