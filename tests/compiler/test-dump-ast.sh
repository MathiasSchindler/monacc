#!/usr/bin/env bash
set -euo pipefail

# Test for --dump-ast flag (Phase 1 debug toggle)
# This test ensures the compiler can dump AST for debugging

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

MONACC_BIN="${MONACC_BIN:-./bin/monacc}"
BUILD_DIR="build/test-dump-ast"

mkdir -p "$BUILD_DIR"

if [[ ! -x "$MONACC_BIN" ]]; then
  echo "test-dump-ast: missing monacc binary at $MONACC_BIN" >&2
  exit 1
fi

# Test 1: Dump AST for simple program
echo "test-dump-ast: testing AST dump..."
"$MONACC_BIN" --dump-ast "$BUILD_DIR/simple.ast" examples/ret42.c -o "$BUILD_DIR/simple"

if [[ ! -f "$BUILD_DIR/simple.ast" ]]; then
  echo "test-dump-ast: AST dump file not created" >&2
  exit 1
fi

# Verify AST dump contains expected content
if ! grep -q "^Functions: 1$" "$BUILD_DIR/simple.ast"; then
  echo "test-dump-ast: AST dump missing function count" >&2
  cat "$BUILD_DIR/simple.ast" >&2
  exit 1
fi

if ! grep -q "main" "$BUILD_DIR/simple.ast"; then
  echo "test-dump-ast: AST dump missing main function" >&2
  cat "$BUILD_DIR/simple.ast" >&2
  exit 1
fi

# Test 2: Dump AST for program with structs
echo "test-dump-ast: testing AST dump with struct..."
"$MONACC_BIN" --dump-ast "$BUILD_DIR/struct.ast" examples/struct.c -o "$BUILD_DIR/struct"

if [[ ! -f "$BUILD_DIR/struct.ast" ]]; then
  echo "test-dump-ast: struct AST dump file not created" >&2
  exit 1
fi

if ! grep -q "^Structs: 1$" "$BUILD_DIR/struct.ast"; then
  echo "test-dump-ast: AST dump missing struct count" >&2
  cat "$BUILD_DIR/struct.ast" >&2
  exit 1
fi

echo "test-dump-ast: ALL TESTS PASSED"
exit 0
