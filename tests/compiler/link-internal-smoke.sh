#!/usr/bin/env bash
set -euo pipefail

# Step 3 smoke test: internal link of a single object with PC32/PLT32 relocations.
# Link and run a small subset of examples that exercise RIP-relative references.

mkdir -p build/test

subset=(hello global_array_store static_local_init)

for ex in "${subset[@]}"; do
  out="build/test/linkint-${ex}"
  ./bin/monacc --emit-obj --link-internal "examples/${ex}.c" -o "$out" >/dev/null 2>&1

  set +e
  "$out" >/dev/null 2>&1
  rc=$?
  set -e

  if [ "$rc" -ne 42 ]; then
    echo "link-internal-smoke: FAIL (${ex}: exit $rc, expected 42)"
    exit 1
  fi
done

cat > build/test/linkint_a.c <<'EOF'
int b(void);
int main(void) {
  return b();
}
EOF

cat > build/test/linkint_b.c <<'EOF'
int b(void) {
  return 42;
}
EOF

out="build/test/linkint-multi"
./bin/monacc --emit-obj --link-internal build/test/linkint_a.c build/test/linkint_b.c -o "$out" >/dev/null 2>&1

set +e
"$out" >/dev/null 2>&1
rc=$?
set -e

if [ "$rc" -ne 42 ]; then
  echo "link-internal-smoke: FAIL (multi: exit $rc, expected 42)"
  exit 1
fi

echo "link-internal-smoke: OK (${#subset[@]} examples + multi)"

# Step 6 smoke: default output is stripped; --keep-shdr keeps section headers.
dbg_out="build/test/linkint-keep-shdr"
./bin/monacc --emit-obj --link-internal --keep-shdr examples/hello.c -o "$dbg_out" >/dev/null 2>&1

sec_dump="$(./bin/monacc --dump-elfsec "$dbg_out" 2>&1)"
echo "$sec_dump" | grep -q "\\.shstrtab"
echo "$sec_dump" | grep -q "\\.text"

sec_dump_stripped="$(./bin/monacc --dump-elfsec build/test/linkint-hello 2>&1)"
echo "$sec_dump_stripped" | grep -q "sections: (none)"

# Step 7 smoke: gc-sections equivalent. Ensure unreferenced large globals/functions
# don't bloat the linked executable.
cat > build/test/linkint_gc.c <<'EOF'
const char big[200000] = {1};

int unused(void) {
  return big[0];
}

int main(void) {
  return 42;
}
EOF

gc_out="build/test/linkint-gc"
./bin/monacc --emit-obj --link-internal build/test/linkint_gc.c -o "$gc_out" >/dev/null 2>&1

set +e
"$gc_out" >/dev/null 2>&1
rc=$?
set -e

if [ "$rc" -ne 42 ]; then
  echo "link-internal-smoke: FAIL (gc: exit $rc, expected 42)"
  exit 1
fi

sz=$(stat -c%s "$gc_out")
if [ "$sz" -ge 60000 ]; then
  echo "link-internal-smoke: FAIL (gc: output too large: $sz bytes)"
  exit 1
fi
