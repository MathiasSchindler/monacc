#!/bin/sh
set -eu

BIN=${1:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}
TMP=${2:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../../lib/testlib.sh"
# --- cat: -n numbers lines (including blank lines) ---
CAT_IN="$TMP/cat_in"
printf 'a\n\nb\n' >"$CAT_IN"
OUT=$($BIN/cat -n "$CAT_IN")
EXP=$(printf '1\ta\n2\t\n3\tb\n')
[ "$OUT" = "$EXP" ] || fail "cat -n unexpected output: '$OUT'"

# --- cat: -b numbers nonblank lines only ---
OUT=$($BIN/cat -b "$CAT_IN")
EXP=$(printf '1\ta\n\n2\tb\n')
[ "$OUT" = "$EXP" ] || fail "cat -b unexpected output: '$OUT'"

# --- cat: -s squeezes consecutive blank lines ---
CAT_S="$TMP/cat_s"
printf 'a\n\n\n\n\nb\n\n\n' >"$CAT_S"
OUT=$($BIN/cat -s "$CAT_S")
EXP=$(printf 'a\n\nb\n\n')
[ "$OUT" = "$EXP" ] || fail "cat -s unexpected output: '$OUT'"

# --- cat: -n -s numbers output lines after squeezing ---
OUT=$($BIN/cat -n -s "$CAT_S")
EXP=$(printf '1\ta\n2\t\n3\tb\n4\t\n')
[ "$OUT" = "$EXP" ] || fail "cat -n -s unexpected output: '$OUT'"

OUT=$(printf 'x\n' | $BIN/cat -n)
EXP=$(printf '1\tx\n')
[ "$OUT" = "$EXP" ] || fail "cat -n (stdin) unexpected output: '$OUT'"

# --- cat: multiple files and '-' means stdin ---
printf 'A' >"$TMP/cat_a"
printf 'B' >"$TMP/cat_b"
OUT=$($BIN/cat "$TMP/cat_a" "$TMP/cat_b")
[ "$OUT" = "AB" ] || fail "cat multiple files unexpected: '$OUT'"

OUT=$(printf 'X' | $BIN/cat -)
[ "$OUT" = "X" ] || fail "cat - (stdin) unexpected: '$OUT'"

OUT=$(printf 'X' | $BIN/cat - "$TMP/cat_b")
[ "$OUT" = "XB" ] || fail "cat stdin+file unexpected: '$OUT'"

OUT=$(printf 'X' | $BIN/cat "$TMP/cat_a" -)
[ "$OUT" = "AX" ] || fail "cat file+stdin unexpected: '$OUT'"

# --- cat -n: line numbering continues across files ---
printf 'a\n' >"$TMP/cat_n1"
printf 'b\n' >"$TMP/cat_n2"
OUT=$($BIN/cat -n "$TMP/cat_n1" "$TMP/cat_n2")
EXP=$(printf '1\ta\n2\tb\n')
[ "$OUT" = "$EXP" ] || fail "cat -n multi-file unexpected: '$OUT'"

# --- cat -n: no newline means same line continues ---
printf 'a' >"$TMP/cat_nonl1"
printf 'b\n' >"$TMP/cat_nonl2"
OUT=$($BIN/cat -n "$TMP/cat_nonl1" "$TMP/cat_nonl2")
EXP=$(printf '1\tab\n')
[ "$OUT" = "$EXP" ] || fail "cat -n across non-newline boundary unexpected: '$OUT'"

# --- head/tail: basic -n behavior on stdin ---
printf '1\n2\n3\n4\n5\n' >"$TMP/lines"
OUT=$("$BIN/head" -n 2 <"$TMP/lines")
[ "$OUT" = "1
2" ] || fail "head -n 2 unexpected output"

OUT=$("$BIN/tail" -n 2 <"$TMP/lines")
[ "$OUT" = "4
5" ] || fail "tail -n 2 unexpected output"

# --- wc: default and -l/-w/-c flags ---
WC_F="$TMP/wc-file"
printf 'a b\nc\td\n\n' >"$WC_F"
WC_LINES=3
WC_WORDS=4
WC_BYTES=$(stat -c %s "$WC_F")

OUT=$($BIN/wc "$WC_F")
[ "$OUT" = "$WC_LINES $WC_WORDS $WC_BYTES $WC_F" ] || fail "wc default unexpected output: '$OUT'"

OUT=$($BIN/wc -l "$WC_F")
[ "$OUT" = "$WC_LINES $WC_F" ] || fail "wc -l unexpected output: '$OUT'"

OUT=$($BIN/wc -w "$WC_F")
[ "$OUT" = "$WC_WORDS $WC_F" ] || fail "wc -w unexpected output: '$OUT'"

OUT=$($BIN/wc -c "$WC_F")
[ "$OUT" = "$WC_BYTES $WC_F" ] || fail "wc -c unexpected output: '$OUT'"

OUT=$(printf 'x y\n' | $BIN/wc)
[ "$OUT" = "1 2 4" ] || fail "wc (stdin) unexpected output: '$OUT'"

OUT=$(printf 'x y\n' | $BIN/wc -lw)
[ "$OUT" = "1 2" ] || fail "wc -lw (stdin) unexpected output: '$OUT'"

# --- head/tail: -c N bytes ---
mark "head/tail"
printf 'abcdef' >"$TMP/bytes"
OUT=$("$BIN/head" -c 3 <"$TMP/bytes")
[ "$OUT" = "abc" ] || fail "head -c 3 unexpected output"

OUT=$("$BIN/tail" -c 3 <"$TMP/bytes")
[ "$OUT" = "def" ] || fail "tail -c 3 unexpected output"

OUT=$(printf 'abcdef' | "$BIN/tail" -c 3)
[ "$OUT" = "def" ] || fail "tail -c 3 (pipe) unexpected output"

# --- tail: -f follow mode (single file) ---
mark "tail -f"
TAILF="$TMP/tailf_in"
TAILF_OUT="$TMP/tailf_out"
printf 'a\n' >"$TAILF"
set +e
"$BIN/tail" -n 0 -f "$TAILF" >"$TAILF_OUT" 2>/dev/null &
TPID=$!
set -e
printf 'b\n' >>"$TAILF"  # may race with tail startup
sleep 0.02
printf 'c\n' >>"$TAILF"  # should be observed reliably

# Poll until we see the second line.
j=0
OUT=""
while [ $j -lt 200 ]; do
  OUT=$(cat "$TAILF_OUT" 2>/dev/null)
  case "$OUT" in
    (*c*) break ;;
  esac
  sleep 0.01
  j=$((j + 1))
done

$BIN/kill -9 "$TPID" >/dev/null 2>&1 || true
set +e
wait "$TPID" >/dev/null 2>&1
set -e
OUT=$(cat "$TAILF_OUT")
case "$OUT" in
  (*c*) : ;;
  (*) fail "tail -f unexpected output: '$OUT'" ;;
esac

# --- paste: merge files line-wise ---
P1="$TMP/paste1"
P2="$TMP/paste2"
printf 'a1\na2\n' >"$P1"
printf 'b1\nb2\nb3\n' >"$P2"

$BIN/paste "$P1" "$P2" >"$TMP/paste_out" || fail "paste failed"
printf 'a1\tb1\na2\tb2\n\tb3\n' >"$TMP/paste_exp"
cmp -s "$TMP/paste_exp" "$TMP/paste_out" || fail "paste output mismatch"

$BIN/paste -d , "$P1" "$P2" >"$TMP/paste_out" || fail "paste -d failed"
printf 'a1,b1\na2,b2\n,b3\n' >"$TMP/paste_exp"
cmp -s "$TMP/paste_exp" "$TMP/paste_out" || fail "paste -d output mismatch"

$BIN/paste -s -d , "$P1" >"$TMP/paste_out" || fail "paste -s failed"
printf 'a1,a2\n' >"$TMP/paste_exp"
cmp -s "$TMP/paste_exp" "$TMP/paste_out" || fail "paste -s output mismatch"

# --- nl: line numbering ---
NLIN="$TMP/nl_in"
printf 'foo\n\nbar\n' >"$NLIN"

$BIN/nl "$NLIN" >"$TMP/nl_out" || fail "nl failed"
printf '     1\tfoo\n\n     2\tbar\n' >"$TMP/nl_exp"
cmp -s "$TMP/nl_exp" "$TMP/nl_out" || fail "nl default output mismatch"

$BIN/nl -ba "$NLIN" >"$TMP/nl_out" || fail "nl -ba failed"
printf '     1\tfoo\n     2\t\n     3\tbar\n' >"$TMP/nl_exp"
cmp -s "$TMP/nl_exp" "$TMP/nl_out" || fail "nl -ba output mismatch"

# --- sort: in-memory, bytewise line sorting ---
mark "sort"
printf 'b\na\nc\n' >"$TMP/sort1"
OUT=$("$BIN/sort" <"$TMP/sort1")
[ "$OUT" = "a
b
c" ] || fail "sort unexpected output"

OUT=$("$BIN/sort" -r <"$TMP/sort1")
[ "$OUT" = "c
b
a" ] || fail "sort -r unexpected output"

printf 'b\na\na\n' >"$TMP/sort2"
OUT=$("$BIN/sort" -u <"$TMP/sort2")
[ "$OUT" = "a
b" ] || fail "sort -u unexpected output"

printf 'b\n' >"$TMP/sort3a"
printf 'a\n' >"$TMP/sort3b"
OUT=$("$BIN/sort" "$TMP/sort3a" "$TMP/sort3b")
[ "$OUT" = "a
b" ] || fail "sort FILE FILE unexpected output"

OUT=$(printf '' | "$BIN/sort")
[ "$OUT" = "" ] || fail "sort empty input should produce empty output"

OUT=$(printf 'x\n' | "$BIN/sort")
[ "$OUT" = "x" ] || fail "sort single-line unexpected output: '$OUT'"

# --- sort: input too large should fail (buffer cap is 4 MiB) ---
# Use a sparse file when possible to keep tests fast.
if command -v truncate >/dev/null 2>&1; then
  truncate -s 4194305 "$TMP/sort_big"
else
  dd if=/dev/zero of="$TMP/sort_big" bs=4096 count=1025 >/dev/null 2>&1
fi
set +e
"$BIN/sort" "$TMP/sort_big" >/dev/null 2>"$TMP/sort_big_err"
RC=$?
set -e
[ $RC -ne 0 ] || fail "sort should fail on oversized input"
[ -s "$TMP/sort_big_err" ] || fail "sort should report error on oversized input"

mark "uniq/tee/tr/cut"

# --- sort: -n numeric sort (leading integer) ---
printf '2\n10\n1\n' >"$TMP/sortn1"
OUT=$("$BIN/sort" -n <"$TMP/sortn1")
[ "$OUT" = "1
2
10" ] || fail "sort -n unexpected output"

printf '  -2\n1\n 10\n0\n' >"$TMP/sortn2"
OUT=$("$BIN/sort" -n <"$TMP/sortn2")
[ "$OUT" = "  -2
0
1
 10" ] || fail "sort -n (spaces/neg) unexpected output"

# --- uniq: streaming adjacent duplicate suppression ---
printf 'a\na\nb\nb\nc\n' >"$TMP/uniq1"
OUT=$("$BIN/uniq" <"$TMP/uniq1")
[ "$OUT" = "a
b
c" ] || fail "uniq unexpected output"

OUT=$("$BIN/uniq" -c <"$TMP/uniq1")
[ "$OUT" = "2 a
2 b
1 c" ] || fail "uniq -c unexpected output"

OUT=$("$BIN/uniq" -d <"$TMP/uniq1")
[ "$OUT" = "a
b" ] || fail "uniq -d unexpected output"

OUT=$("$BIN/uniq" -u <"$TMP/uniq1")
[ "$OUT" = "c" ] || fail "uniq -u unexpected output"

# --- uniq: FILE operands and multiple files are treated as one stream ---
printf 'a\na\n' >"$TMP/uniq_f1"
printf 'a\nb\n' >"$TMP/uniq_f2"
OUT=$("$BIN/uniq" "$TMP/uniq_f1" "$TMP/uniq_f2")
[ "$OUT" = "a
b" ] || fail "uniq FILE FILE unexpected output"

# --- tee: fanout stdin to stdout + files ---
printf 'hi\n' >"$TMP/tee_in"
printf 'hi\n' >"$TMP/tee_expected"
printf 'hi\n' | "$BIN/tee" "$TMP/tee_a" "$TMP/tee_b" >"$TMP/tee_out" || fail "tee failed"
cmp -s "$TMP/tee_expected" "$TMP/tee_out" || fail "tee stdout mismatch"
cmp -s "$TMP/tee_expected" "$TMP/tee_a" || fail "tee file A mismatch"
cmp -s "$TMP/tee_expected" "$TMP/tee_b" || fail "tee file B mismatch"

# --- tee: -a appends instead of truncating ---
printf 'old\n' >"$TMP/tee_append"
printf 'new\n' | "$BIN/tee" -a "$TMP/tee_append" >"$TMP/tee_append_out" || fail "tee -a failed"
[ "$(cat "$TMP/tee_append_out")" = "new" ] || fail "tee -a stdout mismatch"
EXP=$(printf 'old\nnew\n')
[ "$(cat "$TMP/tee_append")" = "$EXP" ] || fail "tee -a did not append"

# --- tee: '-' operand means stdout (should not create a file named '-') ---
OUT=$(cd "$TMP" && printf 'x\n' | "$BIN/tee" -)
[ "$OUT" = "x" ] || fail "tee - unexpected output: '$OUT'"
[ ! -e "$TMP/-" ] || fail "tee should not create a file named '-'"

# --- tee: error on one output continues writing others (and exits 1) ---
mkdir -p "$TMP/tee_dir"
set +e
printf 'hi\n' | "$BIN/tee" "$TMP/tee_ok" "$TMP/tee_dir" >"$TMP/tee_out2" 2>"$TMP/tee_err2"
RC=$?
set -e
[ $RC -eq 1 ] || fail "tee should exit 1 when an output fails (got $RC)"
[ "$(cat "$TMP/tee_out2")" = "hi" ] || fail "tee should still write to stdout on partial failure"
cmp -s "$TMP/tee_expected" "$TMP/tee_ok" || fail "tee should still write to good file on partial failure"
[ -s "$TMP/tee_err2" ] || fail "tee should report error on failing output"

# --- tr: 1:1 bytewise translation ---
printf 'abc\n' >"$TMP/tr_in"
printf 'xyc\n' >"$TMP/tr_expected"
"$BIN/tr" ab xy <"$TMP/tr_in" >"$TMP/tr_out" || fail "tr failed"
cmp -s "$TMP/tr_expected" "$TMP/tr_out" || fail "tr output mismatch"

# --- tr: -d delete ---
OUT=$(printf 'a-b-c\n' | "$BIN/tr" -d '-')
[ "$OUT" = "abc" ] || fail "tr -d unexpected: '$OUT'"

# --- tr: -s squeeze repeats ---
OUT=$(printf 'aaabbb   c\n' | "$BIN/tr" -s ' ab')
[ "$OUT" = "ab c" ] || fail "tr -s unexpected: '$OUT'"

# Combined flags (-ds and -sd)
OUT=$(printf '%s\n' '----a---' | "$BIN/tr" -ds '-')
[ "$OUT" = "a" ] || fail "tr -ds unexpected: '$OUT'"

OUT=$(printf '%s\n' '----a---' | "$BIN/tr" -sd '-')
[ "$OUT" = "a" ] || fail "tr -sd unexpected: '$OUT'"

# Translate + squeeze: translate first, squeeze the translated set (SET2)
OUT=$(printf 'aaabbb\n' | "$BIN/tr" -s ab xy)
[ "$OUT" = "xy" ] || fail "tr -s translate+squeeze unexpected: '$OUT'"

# -- ends option parsing
OUT=$(printf '%s\n' '-' | "$BIN/tr" -- - x)
[ "$OUT" = "x" ] || fail "tr -- end-of-options unexpected: '$OUT'"

OUT=$(printf 'abc\n' | "$BIN/tr" ab x)
[ "$OUT" = "xxc" ] || fail "tr should repeat last SET2 char when shorter (got '$OUT')"

OUT=$(printf 'abcabc\n' | "$BIN/tr" abc x)
[ "$OUT" = "xxxxxx" ] || fail "tr should repeat last SET2 char (3->1) (got '$OUT')"

set +e
printf 'abc\n' | "$BIN/tr" "" "" >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "tr should usage-error on empty sets (got $RC)"

# --- cut: tab-delimited fields (-f) ---
printf 'a\tb\tc\n1\t2\n' >"$TMP/cut_in"
printf 'b\n2\n' >"$TMP/cut_expected1"
"$BIN/cut" -f 2 <"$TMP/cut_in" >"$TMP/cut_out1" || fail "cut -f 2 failed"
cmp -s "$TMP/cut_expected1" "$TMP/cut_out1" || fail "cut -f 2 mismatch"

printf 'a\tc\n1\n' >"$TMP/cut_expected2"
"$BIN/cut" -f 1,3 <"$TMP/cut_in" >"$TMP/cut_out2" || fail "cut -f 1,3 failed"
cmp -s "$TMP/cut_expected2" "$TMP/cut_out2" || fail "cut -f 1,3 mismatch"

printf 'a\tb\n1\t2\n' >"$TMP/cut_expected3"
"$BIN/cut" -f 1-2 <"$TMP/cut_in" >"$TMP/cut_out3" || fail "cut -f 1-2 failed"
cmp -s "$TMP/cut_expected3" "$TMP/cut_out3" || fail "cut -f 1-2 mismatch"

printf '\n\n' >"$TMP/cut_expected4"
printf 'onlyone\n\n' >"$TMP/cut_in2"
"$BIN/cut" -f 2 <"$TMP/cut_in2" >"$TMP/cut_out4" || fail "cut out-of-range field failed"
cmp -s "$TMP/cut_expected4" "$TMP/cut_out4" || fail "cut out-of-range field mismatch"

# --- cut: custom delimiter (-d) ---
printf 'a:b:c\n1:2\n' >"$TMP/cut_in3"
printf 'b\n2\n' >"$TMP/cut_expected5"
"$BIN/cut" -d : -f 2 <"$TMP/cut_in3" >"$TMP/cut_out5" || fail "cut -d : -f 2 failed"
cmp -s "$TMP/cut_expected5" "$TMP/cut_out5" || fail "cut -d : -f 2 mismatch"

