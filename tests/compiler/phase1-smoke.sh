#!/usr/bin/env bash
set -euo pipefail

# PHASE 1 smoke test: minimal compiler invariants
# This test ensures the compiler can compile and run a trivial program.
# It serves as a baseline for all structural refactoring work.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

MONACC_BIN="${MONACC_BIN:-./bin/monacc}"
BUILD_DIR="build/phase1-smoke"

mkdir -p "$BUILD_DIR"

if [[ ! -x "$MONACC_BIN" ]]; then
  echo "phase1-smoke: missing monacc binary at $MONACC_BIN" >&2
  exit 1
fi

# Test 1: Compile and run a trivial return-42 program
cat > "$BUILD_DIR/trivial.c" <<'EOF'
int main(void) {
  return 42;
}
EOF

echo "phase1-smoke: compiling trivial program..."
"$MONACC_BIN" "$BUILD_DIR/trivial.c" -o "$BUILD_DIR/trivial" 2>"$BUILD_DIR/trivial.err"

if [[ ! -x "$BUILD_DIR/trivial" ]]; then
  echo "phase1-smoke: compilation failed" >&2
  cat "$BUILD_DIR/trivial.err" >&2
  exit 1
fi

echo "phase1-smoke: running trivial program..."
set +e
"$BUILD_DIR/trivial"
rc=$?
set -e

if [[ $rc -ne 42 ]]; then
  echo "phase1-smoke: trivial program returned $rc, expected 42" >&2
  exit 1
fi

# Test 2: Compile and run a program with arithmetic
cat > "$BUILD_DIR/simple.c" <<'EOF'
int add(int a, int b) {
  return a + b;
}

int main(void) {
  int x = 10;
  int y = 32;
  return add(x, y);
}
EOF

echo "phase1-smoke: compiling simple program..."
"$MONACC_BIN" "$BUILD_DIR/simple.c" -o "$BUILD_DIR/simple" 2>"$BUILD_DIR/simple.err"

if [[ ! -x "$BUILD_DIR/simple" ]]; then
  echo "phase1-smoke: compilation of simple program failed" >&2
  cat "$BUILD_DIR/simple.err" >&2
  exit 1
fi

echo "phase1-smoke: running simple program..."
set +e
"$BUILD_DIR/simple"
rc=$?
set -e

if [[ $rc -ne 42 ]]; then
  echo "phase1-smoke: simple program returned $rc, expected 42" >&2
  exit 1
fi

# Test 3: Verify self-hosted compiler can also compile trivial program
if [[ -x ./bin/monacc-self ]]; then
  echo "phase1-smoke: testing self-hosted compiler..."
  ./bin/monacc-self "$BUILD_DIR/trivial.c" -o "$BUILD_DIR/trivial-self" 2>"$BUILD_DIR/trivial-self.err"
  
  if [[ ! -x "$BUILD_DIR/trivial-self" ]]; then
    echo "phase1-smoke: self-hosted compilation failed" >&2
    cat "$BUILD_DIR/trivial-self.err" >&2
    exit 1
  fi
  
  set +e
  "$BUILD_DIR/trivial-self"
  rc=$?
  set -e
  
  if [[ $rc -ne 42 ]]; then
    echo "phase1-smoke: self-hosted trivial program returned $rc, expected 42" >&2
    exit 1
  fi
  
  echo "phase1-smoke: self-hosted compiler OK"
else
  echo "phase1-smoke: skipping self-hosted test (bin/monacc-self not found)"
fi

echo "phase1-smoke: ALL TESTS PASSED"
exit 0
