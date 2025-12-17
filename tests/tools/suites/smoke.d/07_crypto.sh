#!/bin/sh
set -eu

BIN=${1:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}
TMP=${2:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../../lib/testlib.sh"

mark "crypto"

# --- sha256: stdin empty ---
OUT=$(printf '' | "$BIN/sha256")
EXP="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -"
assert_eq "sha256 stdin empty" "$EXP" "$OUT"

# --- sha256: stdin 'abc' ---
OUT=$(printf 'abc' | "$BIN/sha256")
EXP="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -"
assert_eq "sha256 stdin abc" "$EXP" "$OUT"

# --- sha256: file 'abc' ---
F="$TMP/sha256_abc"
printf 'abc' >"$F"
OUT=$("$BIN/sha256" "$F")
EXP="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  $F"
assert_eq "sha256 file abc" "$EXP" "$OUT"

# --- sha256: multiple files ---
F2="$TMP/sha256_empty"
printf '' >"$F2"
OUT=$("$BIN/sha256" "$F2" "$F")
EXP=$(printf '%s\n%s' \
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  $F2" \
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  $F")
assert_eq "sha256 multiple files" "$EXP" "$OUT"

# --- hkdf: RFC 5869 test case 1 ---
OUT=$("$BIN/hkdf" --rfc5869-1)
EXP=$(printf '%s\n%s' \
  "prk 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5" \
  "okm 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
assert_eq "hkdf rfc5869 tc1" "$EXP" "$OUT"

# --- aes128: FIPS 197 known-answer vector ---
OUT=$("$BIN/aes128" --fips197)
EXP="69c4e0d86a7b0430d8cdb78070b4c55a"
assert_eq "aes128 fips197" "$EXP" "$OUT"

exit 0
