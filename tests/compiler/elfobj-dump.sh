#!/usr/bin/env bash
set -euo pipefail

MONACC_BIN=${MONACC_BIN:-"$(pwd)/bin/monacc"}

if [[ ! -x "$MONACC_BIN" ]]; then
  echo "elfobj-dump: missing monacc binary at $MONACC_BIN" >&2
  echo "elfobj-dump: run 'make' first" >&2
  exit 1
fi

out_dir="build/elfobj-dump"
mkdir -p "$out_dir"

obj="$out_dir/t.o"
dump_txt="$out_dir/dump.txt"

# Pick a file that forces relocations and touches .bss/.text.
"$MONACC_BIN" --emit-obj -c examples/global_array_store.c -o "$obj" >/dev/null 2>&1

"$MONACC_BIN" --dump-elfobj "$obj" >"$dump_txt" 2>&1

# Sanity assertions: stable, implementation-relevant facts.
grep -q "type=ET_REL" "$dump_txt"
grep -q "machine=EM_X86_64" "$dump_txt"
grep -q "\\.text" "$dump_txt"
grep -q "relocations:" "$dump_txt"
# We expect at least one PC-relative relocation for RIP-relative accesses.
grep -q "R_X86_64_PC32" "$dump_txt"

echo "elfobj-dump: OK"
