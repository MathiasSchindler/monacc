#!/bin/bash
# Test adapter functions for signature compatibility
# This test verifies that the adapter header can be included correctly

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "==> Testing monacc adapter header"

# Test 1: Verify adapter header compiles with host compiler
echo "  Verifying adapter header syntax with host compiler..."
if ! cc -I "$ROOT_DIR/compiler" -I "$ROOT_DIR/core" -fsyntax-only \
    -x c "$ROOT_DIR/compiler/monacc_adapters.h" 2>&1 | grep -v "pragma once in main file"; then
    echo "ERROR: Adapter header has syntax errors"
    exit 1
fi

# Test 2: Verify adapter header can be included in a C file
echo "  Verifying adapter header can be included..."
TEST_C="/tmp/test_adapter_include.c"
cat > "$TEST_C" << 'EOF'
#include "monacc.h"
#include "mc_compiler.h"
#include "monacc_adapters.h"

// This file just tests that the headers can be included together
// without conflicts or syntax errors
EOF

# Compile and check - ignore "pragma once" warnings
if cc -I "$ROOT_DIR/compiler" -I "$ROOT_DIR/core" -fsyntax-only "$TEST_C" 2>&1 | grep -v "pragma once" | grep -q "error"; then
    echo "ERROR: Headers failed to compile"
    cc -I "$ROOT_DIR/compiler" -I "$ROOT_DIR/core" -fsyntax-only "$TEST_C" 2>&1
    exit 1
else
    echo "  Headers compile successfully"
fi

# Test 3: Verify the documentation exists
if [ ! -f "$ROOT_DIR/docs/adapters.md" ]; then
    echo "ERROR: Adapter documentation not found"
    exit 1
fi

echo "==> Adapter header tests PASSED"
echo ""
echo "Note: The adapter macros are designed for external code that calls"
echo "      compiler functions programmatically. They create temporary"
echo "      contexts for backward compatibility during Phase 2 migration."
echo ""
echo "Usage example:"
echo "  #include \"monacc_adapters.h\""
echo "  "
echo "  // Old code without context:"
echo "  MONACC_CALL_NOCTX(emit_x86_64_sysv_freestanding, &prg, &out);"
echo "  "
echo "  // New code with explicit context:"
echo "  mc_compiler ctx;"
echo "  mc_compiler_init(&ctx);"
echo "  emit_x86_64_sysv_freestanding(&ctx, &prg, &out);"
echo "  mc_compiler_destroy(&ctx);"
exit 0