#!/bin/sh
set -eu

# Guardrail: kernel is allowed to use host binutils/GRUB tooling.
# The rest of the repo should not start depending on these tools.
#
# This test intentionally matches only very specific invocation patterns to
# avoid false positives in docs.

root_dir=${1:-.}

fail=0

check() {
  pattern="$1"
  desc="$2"

  # Search everywhere except kernel/.
  # Exclude common doc/metadata formats to avoid noise.
  if grep -RInE "$pattern" \
      --exclude-dir=kernel \
      --exclude-dir=.git \
      --exclude-dir=build \
      --exclude=no-kernel-binutils-creep.sh \
      --exclude=*.md \
      --exclude=*.html \
      --exclude=*.tsv \
      --exclude=*.txt \
      "$root_dir" >/dev/null 2>&1; then
    echo "FAIL: kernel-only dependency crept outside kernel/: $desc" >&2
    echo "  pattern: $pattern" >&2
    echo "  matches:" >&2
    grep -RInE "$pattern" \
      --exclude-dir=kernel \
      --exclude-dir=.git \
      --exclude-dir=build \
      --exclude=no-kernel-binutils-creep.sh \
      --exclude=*.md \
      --exclude=*.html \
      --exclude=*.tsv \
      --exclude=*.txt \
      "$root_dir" | head -n 50 >&2
    fail=1
  fi
}

check '(^|[^A-Za-z0-9_])grub-mkrescue([^A-Za-z0-9_]|$)' 'grub-mkrescue usage'
check '(^|[^A-Za-z0-9_])as[[:space:]]+--64([^A-Za-z0-9_]|$)' 'as --64 invocation'
check '(^|[^A-Za-z0-9_])ld[[:space:]]+-nostdlib([^A-Za-z0-9_]|$)' 'ld -nostdlib invocation'
check '^AS[[:space:]]*\?=[[:space:]]*as([[:space:]]|$)' 'Makefile AS ?= as'
check '^LD[[:space:]]*\?=[[:space:]]*ld([[:space:]]|$)' 'Makefile LD ?= ld'

exit "$fail"
