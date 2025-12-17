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

# --- gcm128: NIST SP 800-38D test case 3 (no AAD) ---
OUT=$("$BIN/gcm128" --nist-sp800-38d-tc3)
EXP=$(printf '%s\n%s' \
  "ct 42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985" \
  "tag 4d5c2af327cd64a62cf35abd2ba6fab4")
assert_eq "gcm128 nist sp800-38d tc3" "$EXP" "$OUT"

# --- x25519: RFC 7748 test vector ---
OUT=$("$BIN/x25519" --rfc7748-1)
EXP="shared 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
assert_eq "x25519 rfc7748" "$EXP" "$OUT"

# --- tls13 rec: TLS 1.3 record layer smoke ---
OUT=$("$BIN/tls13" rec --smoke)
EXP="1703030016ed7598c33eea12a40329c24d134846df5a506994539d"
assert_eq "tlsrec record smoke" "$EXP" "$OUT"

# --- tls13 kdf: TLS 1.3 key schedule (RFC 8448 sample) ---
OUT=$("$BIN/tls13" kdf --rfc8448-1rtt)
EXP=$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
  "early 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a" \
  "derived 6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba" \
  "handshake 1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac" \
  "c_hs b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21" \
  "s_hs b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38" \
  "c_key dbfaa693d1762c5b666af5d950258d01" \
  "c_iv 5bd3c71b836e0b76bb73265f" \
  "s_key 3fce516009c21727d0f2e4e86ee403bc" \
  "s_iv 5d313eb2671276ee13000b30")
assert_eq "tls13kdf rfc8448 1rtt" "$EXP" "$OUT"

# --- tls13 hello: TLS 1.3 ClientHello/ServerHello + transcript hash (RFC 8448) ---
OUT=$("$BIN/tls13" hello --rfc8448-1rtt)
EXP="chsh_hash 860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
assert_eq "tls13hello rfc8448 ch+sh transcript" "$EXP" "$OUT"

exit 0
