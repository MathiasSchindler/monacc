#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/docs/wasm"
BIN_DIR="$OUT_DIR/bin"

EMCC="${EMCC:-emcc}"

mkdir -p "$BIN_DIR"

COMMON_FLAGS=(
  -Os
  -sWASM=1
  -sALLOW_MEMORY_GROWTH=1
  -sEXIT_RUNTIME=1
  -sFORCE_FILESYSTEM=1
  -sMODULARIZE=1
  -sENVIRONMENT=web
)

INCLUDES=(
  -I"$ROOT_DIR/core"
  -I"$ROOT_DIR/compiler"
  -I"$ROOT_DIR/tools"
)

CORE_SRCS=("$ROOT_DIR"/core/*.c)

echo "[emscripten] building monacc..."
"$EMCC" "${COMMON_FLAGS[@]}" "${INCLUDES[@]}" \
  "${CORE_SRCS[@]}" "$ROOT_DIR"/compiler/*.c \
  -o "$OUT_DIR/monacc.js"

echo "[emscripten] building tools..."
for src in "$ROOT_DIR"/tools/*.c; do
  name="$(basename "$src" .c)"
  extra=()
  if [[ "$name" == "masto" ]]; then
    extra=("$ROOT_DIR"/tools/masto/*.c)
  fi
  "$EMCC" "${COMMON_FLAGS[@]}" "${INCLUDES[@]}" \
    "${CORE_SRCS[@]}" "$src" "${extra[@]}" \
    -o "$BIN_DIR/$name.js"
done

echo "[emscripten] output written to $OUT_DIR"