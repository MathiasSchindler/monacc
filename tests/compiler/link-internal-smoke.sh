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

# Regression: ensure internal assembler supports cdqe/cltq-style sign-extension.
# This used to fail after codegen started emitting `cdqe` as a shorter alternative
# to `movslq %eax, %rax`.
cat > build/test/linkint_cdqe.c <<'EOF'
long f(int x) {
  return x;
}

int main(void) {
  return (f(-1) == -1) ? 42 : 0;
}
EOF

out="build/test/linkint-cdqe"
./bin/monacc --emit-obj --link-internal build/test/linkint_cdqe.c -o "$out" >/dev/null 2>&1

set +e
"$out" >/dev/null 2>&1
rc=$?
set -e

if [ "$rc" -ne 42 ]; then
  echo "link-internal-smoke: FAIL (cdqe: exit $rc, expected 42)"
  exit 1
fi

cat > build/test/linkint_forward_relax.c <<'EOF'
long got_jmp;
long got_jcc;
int main(void) {
  __asm__ volatile(
      ".Ljmp_start:\n"
      "jmp .Ljmp_after\n"
      ".Ljmp_after:\n"
      "leaq .Ljmp_after(%rip), %rax\n"
      "leaq .Ljmp_start(%rip), %rcx\n"
      "subq %rcx, %rax\n"
      "movq %rax, got_jmp(%rip)\n"
      "xorl %eax, %eax\n"
      ".Ljcc_start:\n"
      "je .Ljcc_after\n"
      ".Ljcc_after:\n"
      "leaq .Ljcc_after(%rip), %rax\n"
      "leaq .Ljcc_start(%rip), %rcx\n"
      "subq %rcx, %rax\n"
      "movq %rax, got_jcc(%rip)\n"
      :
      :
      : "rax", "rcx", "cc", "memory");
  return (got_jmp == 2 && got_jcc == 2) ? 42 : 0;
}
EOF

out="build/test/linkint-forward-relax"
./bin/monacc --emit-obj --link-internal build/test/linkint_forward_relax.c -o "$out" >/dev/null 2>&1

set +e
"$out" >/dev/null 2>&1
rc=$?
set -e

if [ "$rc" -ne 42 ]; then
  echo "link-internal-smoke: FAIL (forward-relax: exit $rc, expected 42)"
  exit 1
fi

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

echo "link-internal-smoke: OK (${#subset[@]} examples + cdqe + forward-relax + multi)"

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

# Step 8 regression: BSS-only RW segment should not force file padding.
cat > build/test/linkint_bssonly.c <<'EOF'
static unsigned char big_bss[65536];
int main(void) {
  return (int)big_bss[0];
}
EOF

bss_out="build/test/linkint-bssonly"
./bin/monacc --emit-obj --link-internal build/test/linkint_bssonly.c -o "$bss_out" >/dev/null 2>&1

sz=$(stat -c%s "$bss_out" 2>/dev/null || echo 0)
# Historically this regressed to >=8192 due to RW p_offset being page-aligned
# even when p_filesz==0.
if [ "$sz" -ge 8192 ]; then
  echo "link-internal-smoke: FAIL (bssonly: output too large: $sz bytes)"
  exit 1
fi

# Step 9 smoke: conservative ICF + rodata dedup should shrink many identical
# local .text.* and .rodata.* sections while preserving behavior.
cat > build/test/linkint_icf_rodata.c <<'EOF'
#define BLOB "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

static int f1(void) { return 1; }
static int f2(void) { return 1; }
static int f3(void) { return 1; }
static int f4(void) { return 1; }
static int f5(void) { return 1; }
static int f6(void) { return 1; }
static int f7(void) { return 1; }
static int f8(void) { return 1; }
static int f9(void) { return 1; }
static int f10(void) { return 1; }
static int f11(void) { return 1; }
static int f12(void) { return 1; }
static int f13(void) { return 1; }
static int f14(void) { return 1; }
static int f15(void) { return 1; }
static int f16(void) { return 1; }

int main(void) {
  int v = 0;
  v += f1() + f2() + f3() + f4() + f5() + f6() + f7() + f8();
  v += f9() + f10() + f11() + f12() + f13() + f14() + f15() + f16();
  v += BLOB[0] + BLOB[0] + BLOB[0] + BLOB[0] + BLOB[0] + BLOB[0] + BLOB[0] + BLOB[0];
  v += BLOB[0] + BLOB[0] + BLOB[0] + BLOB[0] + BLOB[0] + BLOB[0] + BLOB[0] + BLOB[0];
  return (v == 1056) ? 42 : 0;
}
EOF

icf_out="build/test/linkint-icf-rodata"
./bin/monacc --emit-obj --link-internal build/test/linkint_icf_rodata.c -o "$icf_out" >/dev/null 2>&1

set +e
"$icf_out" >/dev/null 2>&1
rc=$?
set -e

if [ "$rc" -ne 42 ]; then
  echo "link-internal-smoke: FAIL (icf-rodata: exit $rc, expected 42)"
  exit 1
fi

sz=$(stat -c%s "$icf_out")
if [ "$sz" -ge 9000 ]; then
  echo "link-internal-smoke: FAIL (icf-rodata: output too large: $sz bytes)"
  exit 1
fi

# Optional oracle check: if external `ld` is available, build one tool both ways
# and compare its observable behavior. This catches subtle link/layout regressions
# without making external ld a hard dependency.
if command -v ld >/dev/null 2>&1; then
  oracle_out_ld="build/test/oracle-echo-ld"
  oracle_out_int="build/test/oracle-echo-int"

  # External ld path (forced)
  ./bin/monacc --emit-obj --ld ld -I core tools/echo.c \
    core/mc_str.c core/mc_fmt.c core/mc_snprint.c core/mc_libc_compat.c \
    core/mc_start_env.c core/mc_io.c core/mc_regex.c \
    -o "$oracle_out_ld" >/dev/null 2>&1

  # Internal linker path
  ./bin/monacc --emit-obj --link-internal -I core tools/echo.c \
    core/mc_str.c core/mc_fmt.c core/mc_snprint.c core/mc_libc_compat.c \
    core/mc_start_env.c core/mc_io.c core/mc_regex.c \
    -o "$oracle_out_int" >/dev/null 2>&1

  out_ld="$($oracle_out_ld -n hello 2>/dev/null || true)"
  out_int="$($oracle_out_int -n hello 2>/dev/null || true)"

  if [ "$out_ld" != "$out_int" ]; then
    echo "link-internal-smoke: FAIL (oracle: echo output mismatch)"
    exit 1
  fi
else
  echo "link-internal-smoke: SKIP oracle (no external ld in PATH)"
fi
