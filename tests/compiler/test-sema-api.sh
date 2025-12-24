#!/usr/bin/env bash
set -euo pipefail

# Test for semantic analysis API (sema_analyze and sema_validate)
# This test ensures the stable frontend API works correctly

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

MONACC_BIN="${MONACC_BIN:-./bin/monacc}"
BUILD_DIR="build/test-sema-api"

mkdir -p "$BUILD_DIR"

if [[ ! -x "$MONACC_BIN" ]]; then
  echo "test-sema-api: missing monacc binary at $MONACC_BIN" >&2
  exit 1
fi

# Test 1: Verify sema phase is called during compilation
echo "test-sema-api: testing sema phase execution..."
if ! "$MONACC_BIN" --trace-selfhost examples/ret42.c -o "$BUILD_DIR/ret42" 2>&1 | grep -q "sema start"; then
  echo "test-sema-api: sema phase not executed" >&2
  exit 1
fi

if ! "$MONACC_BIN" --trace-selfhost examples/ret42.c -o "$BUILD_DIR/ret42" 2>&1 | grep -q "sema end"; then
  echo "test-sema-api: sema phase did not complete" >&2
  exit 1
fi

# Test 2: Verify sema phase is called between parse and codegen
echo "test-sema-api: testing sema phase ordering..."
TRACE_OUTPUT=$("$MONACC_BIN" --trace-selfhost examples/ret42.c -o "$BUILD_DIR/ret42" 2>&1)

# Check ordering: parse -> sema -> codegen
if ! echo "$TRACE_OUTPUT" | grep -A 3 "parse end" | grep -q "sema start"; then
  echo "test-sema-api: sema phase not called after parse" >&2
  echo "$TRACE_OUTPUT" >&2
  exit 1
fi

if ! echo "$TRACE_OUTPUT" | grep -A 3 "sema end" | grep -q "codegen start"; then
  echo "test-sema-api: codegen not called after sema" >&2
  echo "$TRACE_OUTPUT" >&2
  exit 1
fi

# Test 3: Verify compilation succeeds with sema phase
echo "test-sema-api: testing successful compilation..."
if [[ ! -x "$BUILD_DIR/ret42" ]]; then
  echo "test-sema-api: compilation did not produce executable" >&2
  exit 1
fi

# Test 4: Verify compiled program runs correctly
echo "test-sema-api: testing compiled program execution..."
"$BUILD_DIR/ret42" || EXIT_CODE=$?
if [[ ${EXIT_CODE:-0} -ne 42 ]]; then
  echo "test-sema-api: compiled program returned ${EXIT_CODE:-0} instead of 42" >&2
  exit 1
fi

# Test 5: Verify sema works with complex programs
echo "test-sema-api: testing sema with struct program..."
if ! "$MONACC_BIN" --trace-selfhost examples/struct.c -o "$BUILD_DIR/struct" 2>&1 | grep -q "sema start"; then
  echo "test-sema-api: sema phase not executed for struct program" >&2
  exit 1
fi

if [[ ! -x "$BUILD_DIR/struct" ]]; then
  echo "test-sema-api: struct program compilation failed" >&2
  exit 1
fi

"$BUILD_DIR/struct" || EXIT_CODE=$?
if [[ ${EXIT_CODE:-0} -ne 42 ]]; then
  echo "test-sema-api: struct program returned ${EXIT_CODE:-0} instead of 42" >&2
  exit 1
fi

# Test 6: Verify sema works with function pointers
echo "test-sema-api: testing sema with function pointer program..."
if ! "$MONACC_BIN" --trace-selfhost examples/fnptr_member.c -o "$BUILD_DIR/fnptr" 2>&1 | grep -q "sema end"; then
  echo "test-sema-api: sema phase did not complete for function pointer program" >&2
  exit 1
fi

if [[ ! -x "$BUILD_DIR/fnptr" ]]; then
  echo "test-sema-api: function pointer program compilation failed" >&2
  exit 1
fi

"$BUILD_DIR/fnptr" || EXIT_CODE=$?
if [[ ${EXIT_CODE:-0} -ne 42 ]]; then
  echo "test-sema-api: function pointer program returned ${EXIT_CODE:-0} instead of 42" >&2
  exit 1
fi

echo "test-sema-api: ALL TESTS PASSED"
exit 0
