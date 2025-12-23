# Phase 1: Compiler Invariants and Safeguards

## Overview

Phase 1 establishes baseline testing and debugging infrastructure to ensure the compiler's fundamental behaviors remain stable throughout the structural rebase.

## Components Added

### 1. Smoke Tests (`tests/compiler/phase1-smoke.sh`)

A minimal test suite that validates:
- Basic compiler operation (can compile and run trivial programs)
- Simple arithmetic and function calls work correctly
- Self-hosted compiler (if available) produces working binaries

**Usage:**
```bash
# Run the smoke tests directly
bash tests/compiler/phase1-smoke.sh

# Or via make (included in test suite)
make test SELFTEST_PHASE1=1

# Disable phase1 tests
make test SELFTEST_PHASE1=0
```

### 2. CI Integration (`.github/workflows/phase1-smoke.yml`)

GitHub Actions workflow that:
- Builds `bin/monacc` (bootstrap compiler)
- Builds `bin/monacc-self` (self-hosted compiler)
- Runs all Phase 1 smoke tests
- Verifies self-hosted compiler can compile trivial programs

**Triggers:**
- Push to main/master branches
- Push to copilot/** branches  
- Pull requests to main/master

### 3. Debug Toggles (Existing)

The compiler already provides several debug/dump options useful during refactoring:

```bash
# Dump preprocessed output
monacc --dump-pp output.i input.c -o program

# Dump ELF object file internals (symbols, sections, relocs)
monacc --dump-elfobj file.o

# Dump ELF section information
monacc --dump-elfsec executable

# Trace self-hosting compilation steps
monacc --trace-selfhost input.c -o output

# Keep section headers in output (don't strip)
monacc --keep-shdr input.c -o output
```

## Test Coverage

Phase 1 tests ensure:

1. **Trivial Programs**: The compiler can handle the simplest possible C programs
   ```c
   int main(void) { return 42; }
   ```

2. **Basic Arithmetic**: Functions and arithmetic operations work
   ```c
   int add(int a, int b) { return a + b; }
   int main(void) { return add(10, 32); }
   ```

3. **Self-Hosting**: The compiler can compile itself and produce working binaries
   - Verifies `bin/monacc` → `bin/monacc-self`
   - Verifies `bin/monacc-self` can compile test programs

## Integration with Test Suite

Phase 1 tests are integrated into the main `make test` target:

- Run early in the test sequence (after examples, before tools)
- Can be toggled with `SELFTEST_PHASE1=0`
- Failure blocks the entire test suite (fundamental invariant)
- Included in CI for all branches and PRs

## Next Steps

With Phase 1 complete, we have:
- ✅ Baseline smoke tests that must always pass
- ✅ CI enforcement of fundamental invariants
- ✅ Debug facilities for examining intermediate outputs

This foundation allows us to safely proceed with:
- **Phase 2**: Introduce compiler context object
- **Phase 3**: Split monolithic headers into modules
- **Phase 4+**: Structural refactoring of frontend/backend

Any breakage in Phase 1 tests during subsequent phases indicates a regression in fundamental compiler behavior.
