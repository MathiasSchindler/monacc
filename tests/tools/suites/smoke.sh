#!/bin/sh
set -eu

BIN=${1:?usage: smoke.sh /path/to/sysbox/bin /path/to/tmpdir}
TMP=${2:?usage: smoke.sh /path/to/sysbox/bin /path/to/tmpdir}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../lib/testlib.sh"

mark "smoke"

SMOKE_DIR="$SELF_DIR/smoke.d"
for part in \
  "$SMOKE_DIR/01_fs.sh" \
  "$SMOKE_DIR/02_text.sh" \
  "$SMOKE_DIR/03_proc.sh" \
  "$SMOKE_DIR/04_cmp_misc.sh" \
  "$SMOKE_DIR/05_sys_shell_text.sh" \
  "$SMOKE_DIR/06_find_stat_df_du_grep_ls.sh" \
  "$SMOKE_DIR/07_crypto.sh" \
  "$SMOKE_DIR/08_mandelbrot.sh"; do
  [ -f "$part" ] || fail "missing smoke part: $part"
  sh "$part" "$BIN" "$TMP"
done

exit 0

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

set +e
printf 'abc\n' | "$BIN/tr" ab x >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "tr should usage-error on mismatched set lengths (got $RC)"

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

# --- date: epoch seconds (numeric) ---
mark "date/sleep/kill/id/which"
OUT=$($BIN/date)
case "$OUT" in
  (""|*[!0-9]*) fail "date output not numeric: '$OUT'" ;;
esac

# --- sleep: integer seconds ---
$BIN/sleep 0 || fail "sleep 0 failed"

set +e
$BIN/sleep >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "sleep should usage-error with no args (got $RC)"

set +e
$BIN/sleep nope >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "sleep should usage-error on invalid seconds (got $RC)"

# --- kill: send signals to a background process ---
(
  $BIN/sleep 2 &
  PID=$!
  $BIN/kill "$PID" || exit 1
  set +e
  wait "$PID"
  WRC=$?
  set -e
  [ $WRC -ne 0 ] || exit 1
) 2>/dev/null || fail "kill default (SIGTERM) failed"

(
  $BIN/sleep 2 &
  PID=$!
  $BIN/kill -9 "$PID" || exit 1
  set +e
  wait "$PID"
  WRC=$?
  set -e
  [ $WRC -ne 0 ] || exit 1
) 2>/dev/null || fail "kill -9 failed"

OUT=$($BIN/kill -l | $BIN/head -n 1)
case "$OUT" in
  (""|*[!0-9]*) fail "kill -l output not numeric: '$OUT'" ;;
esac

# --- id: print uid/gid/groups ---
U=$(id -u)
G=$(id -g)
GRP=$(id -G | tr ' ' ',')
OUT=$($BIN/id)
[ "$OUT" = "uid=$U gid=$G groups=$GRP" ] || fail "id unexpected output: '$OUT'"

# --- whoami: minimal numeric uid ---
OUT=$($BIN/whoami)
[ "$OUT" = "$(id -u)" ] || fail "whoami unexpected output: '$OUT'"

OUT=$($BIN/id -u)
[ "$OUT" = "$U" ] || fail "id -u unexpected: '$OUT'"

OUT=$($BIN/id -g)
[ "$OUT" = "$G" ] || fail "id -g unexpected: '$OUT'"

set +e
$BIN/id extra >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "id should reject operands (got $RC)"

# --- which: locate executables in PATH ---
WHBIN="$TMP/whichbin"
mkdir -p "$WHBIN"
ln -s "$BIN/echo" "$WHBIN/mycmd"

OUT=$(PATH="$WHBIN" $BIN/which mycmd)
[ "$OUT" = "$WHBIN/mycmd" ] || fail "which basic unexpected: '$OUT'"

OUT=$($BIN/which "$BIN/echo")
[ "$OUT" = "$BIN/echo" ] || fail "which /path unexpected: '$OUT'"

mark "post-which"

cp "$BIN/true" "$TMP/localcmd"
$BIN/chmod 755 "$TMP/localcmd" || fail "chmod for which test failed"
OUT=$(cd "$TMP" && PATH=":$WHBIN" $BIN/which localcmd)
[ "$OUT" = "localcmd" ] || fail "which empty PATH segment unexpected: '$OUT'"

# which -a: print all matches in PATH order
P1="$TMP/whichp1"
P2="$TMP/whichp2"
mkdir -p "$P1" "$P2"
cp "$BIN/true" "$P1/dup"
cp "$BIN/true" "$P2/dup"
OUT=$(PATH="$P1:$P2" $BIN/which -a dup)
[ "$OUT" = "$P1/dup
$P2/dup" ] || fail "which -a unexpected: '$OUT'"

set +e
$BIN/which definitely_not_a_command >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 1 ] || fail "which should exit 1 when not found (got $RC)"

# --- ln: hard link ---
mark "ln"
printf 'hello' >"$TMP/ln_src"
"$BIN/ln" "$TMP/ln_src" "$TMP/ln_dst" || fail "ln failed"
[ "$(stat -c %i "$TMP/ln_src")" = "$(stat -c %i "$TMP/ln_dst")" ] || fail "ln did not create a hard link"

# --- ln: -s creates symlink ---
"$BIN/ln" -s "targetfile" "$TMP/ln_sym" || fail "ln -s failed"
OUT=$($BIN/readlink "$TMP/ln_sym")
[ "$OUT" = "targetfile" ] || fail "ln -s produced wrong target: '$OUT'"

# --- ln: -f replaces existing dst ---
printf 'A' >"$TMP/ln_src2"
printf 'B' >"$TMP/ln_dst2"
"$BIN/ln" -f "$TMP/ln_src2" "$TMP/ln_dst2" || fail "ln -f failed"
[ "$(stat -c %i "$TMP/ln_src2")" = "$(stat -c %i "$TMP/ln_dst2")" ] || fail "ln -f did not replace dst with hard link"

# --- ln: -sf replaces existing symlink ---
"$BIN/ln" -s "old" "$TMP/ln_sym2" || fail "ln -s (old) failed"
"$BIN/ln" -sf "new" "$TMP/ln_sym2" || fail "ln -sf failed"
OUT=$($BIN/readlink "$TMP/ln_sym2")
[ "$OUT" = "new" ] || fail "ln -sf produced wrong target: '$OUT'"

mark "after-ln"

# --- readlink: print symlink target ---
mark "readlink"
ln -s "targetfile" "$TMP/rl_symlink"
OUT=$($BIN/readlink "$TMP/rl_symlink")
[ "$OUT" = "targetfile" ] || fail "readlink unexpected output"

# --- readlink: -f canonicalize (absolute path, resolve symlinks, normalize . and ..) ---
mark "readlink -f"
mkdir -p "$TMP/rlf/base/sub"
printf 'z' >"$TMP/rlf/base/sub/file"

OUT=$($BIN/readlink -f "$TMP/rlf/base/sub/file")
[ "$OUT" = "$TMP/rlf/base/sub/file" ] || fail "readlink -f (absolute file) unexpected output: '$OUT'"

OUT=$(cd "$TMP/rlf" && $BIN/readlink -f base/sub/file)
[ "$OUT" = "$TMP/rlf/base/sub/file" ] || fail "readlink -f (relative file) unexpected output: '$OUT'"

ln -s "base/sub/file" "$TMP/rlf/link1"
ln -s "link1" "$TMP/rlf/link2"
OUT=$($BIN/readlink -f "$TMP/rlf/link2")
[ "$OUT" = "$TMP/rlf/base/sub/file" ] || fail "readlink -f (symlink chain) unexpected output: '$OUT'"

OUT=$($BIN/readlink -f "$TMP/rlf/base/./sub/../sub/file")
[ "$OUT" = "$TMP/rlf/base/sub/file" ] || fail "readlink -f (dotdot) unexpected output: '$OUT'"

ln -s "loop2" "$TMP/rlf/loop1"
ln -s "loop1" "$TMP/rlf/loop2"
mark "readlink -f loop"
set +e
$BIN/readlink -f "$TMP/rlf/loop1" >"$TMP/out" 2>"$TMP/err"
RC=$?
set -e
[ $RC -ne 0 ] || fail "readlink -f should fail on symlink loop"
[ -s "$TMP/err" ] || fail "readlink -f loop should print an error"

mark "after-readlink"

# --- realpath: same as readlink -f, via argv0 mode switch ---
mark "realpath"
OUT=$($BIN/realpath "$TMP/rlf/link2")
[ "$OUT" = "$TMP/rlf/base/sub/file" ] || fail "realpath (symlink chain) unexpected output: '$OUT'"

OUT=$(cd "$TMP/rlf" && $BIN/realpath -- base/sub/file)
[ "$OUT" = "$TMP/rlf/base/sub/file" ] || fail "realpath (relative) unexpected output: '$OUT'"

mark "after-realpath"

# --- basename/dirname: pure string logic ---
OUT=$($BIN/basename /a/b/c)
[ "$OUT" = "c" ] || fail "basename /a/b/c unexpected"

OUT=$($BIN/basename /a/b/c/)
[ "$OUT" = "c" ] || fail "basename /a/b/c/ unexpected"

OUT=$($BIN/basename /a/b/c .c)
[ "$OUT" = "c" ] || fail "basename suffix strip unexpected"

OUT=$($BIN/dirname /a/b/c)
[ "$OUT" = "/a/b" ] || fail "dirname /a/b/c unexpected"

OUT=$($BIN/dirname c)
[ "$OUT" = "." ] || fail "dirname c unexpected"

OUT=$($BIN/dirname /)
[ "$OUT" = "/" ] || fail "dirname / unexpected"

mark "touch"

# --- touch: create if missing; do not truncate if existing ---
MISSING="$TMP/touch-missing"
"$BIN/touch" "$MISSING" || fail "touch failed to create missing file"
[ -f "$MISSING" ] || fail "touch did not create missing file"

EXISTING="$TMP/touch-existing"
printf 'abc' >"$EXISTING"
"$BIN/touch" "$EXISTING" || fail "touch failed on existing file"
[ "$(wc -c <"$EXISTING")" -eq 3 ] || fail "touch unexpectedly changed file size"

# --- touch: -t sets mtime (UTC epoch) ---
STAMP="202512120102.03"
# GNU `date -u -d` does not necessarily parse the input in UTC; force UTC for parsing.
EXP=$(TZ=UTC date -d '2025-12-12 01:02:03' +%s)
TFILE="$TMP/touch-stamp"
printf 'x' >"$TFILE"
"$BIN/touch" -t "$STAMP" "$TFILE" || fail "touch -t failed"
GOT=$(stat -c %Y "$TFILE")
[ "$GOT" = "$EXP" ] || fail "touch -t did not set expected mtime (got $GOT, exp $EXP)"

# --- touch: without -t updates mtime to now ---
TFILE2="$TMP/touch-now"
printf 'x' >"$TFILE2"
"$BIN/touch" -t 200001010000.00 "$TFILE2" || fail "touch -t (setup) failed"
M1=$(stat -c %Y "$TFILE2")
"$BIN/touch" "$TFILE2" || fail "touch (update) failed"
M2=$(stat -c %Y "$TFILE2")
[ "$M2" -gt "$M1" ] || fail "touch did not update mtime (m1 $M1, m2 $M2)"

mark "chmod/chown/printf"

mark "cmp/diff/time/ps/who"

# --- cmp: equal and different files ---
CMP1="$TMP/cmp1"
CMP2="$TMP/cmp2"
printf 'abc\n' >"$CMP1"
printf 'abc\n' >"$CMP2"
"$BIN/cmp" "$CMP1" "$CMP2" || fail "cmp equal files should exit 0"

printf 'abc\n' >"$CMP1"
printf 'abX\n' >"$CMP2"
set +e
"$BIN/cmp" "$CMP1" "$CMP2" >"$TMP/out" 2>"$TMP/err"
RC=$?
set -e
[ $RC -eq 1 ] || fail "cmp different files should exit 1 (got $RC)"
[ -s "$TMP/err" ] || fail "cmp should print a diagnostic on difference"

# --- diff: no output when same; show first differing line when different ---
printf 'a\nb\n' >"$TMP/diff1"
printf 'a\nb\n' >"$TMP/diff2"
OUT=$("$BIN/diff" "$TMP/diff1" "$TMP/diff2")
[ -z "$OUT" ] || fail "diff same files should print nothing (got '$OUT')"

printf 'a\nb\n' >"$TMP/diff1"
printf 'a\nX\n' >"$TMP/diff2"
set +e
OUT=$("$BIN/diff" "$TMP/diff1" "$TMP/diff2")
RC=$?
set -e
[ $RC -eq 1 ] || fail "diff different files should exit 1 (got $RC)"
printf '%s' "$OUT" | "$BIN/grep" -q "diff: line" || fail "diff output should mention line"

# --- time: runs command and prints timing to stderr ---
OUT=$("$BIN/time" "$BIN/true" 2>&1)
printf '%s' "$OUT" | "$BIN/grep" -q "real " || fail "time should print 'real ' (got '$OUT')"

# --- ps: prints header and at least one process ---
OUT=$("$BIN/ps" | "$BIN/head" -n 1)
[ "$OUT" = "PID PPID S CMD" ] || fail "ps header unexpected (got '$OUT')"
NLINES=$("$BIN/ps" | "$BIN/wc" -l)
[ "$NLINES" -ge 2 ] || fail "ps should list at least one process (got $NLINES lines)"

# --- pstree: prints header and at least one process ---
OUT=$("$BIN/pstree" | "$BIN/head" -n 1)
[ "$OUT" = "PID PPID S CMD" ] || fail "pstree header unexpected (got '$OUT')"
NLINES=$("$BIN/pstree" | "$BIN/wc" -l)
[ "$NLINES" -ge 2 ] || fail "pstree should list at least one process (got $NLINES lines)"

# --- who: should not fail even if utmp is missing ---
"$BIN/who" >"$TMP/out" 2>"$TMP/err" || fail "who should not fail"

# --- chmod: numeric (octal) modes ---
CHMOD_F="$TMP/chmod-file"
printf 'x' >"$CHMOD_F"
"$BIN/chmod" 600 "$CHMOD_F" || fail "chmod 600 failed"
MODE=$(stat -c %a "$CHMOD_F")
[ "$MODE" = "600" ] || fail "chmod did not set expected mode (got $MODE)"

# --- chmod: symbolic modes ---
"$BIN/chmod" u+x "$CHMOD_F" || fail "chmod u+x failed"
MODE=$(stat -c %a "$CHMOD_F")
[ "$MODE" = "700" ] || fail "chmod u+x expected 700 (got $MODE)"

"$BIN/chmod" go+r "$CHMOD_F" || fail "chmod go+r failed"
MODE=$(stat -c %a "$CHMOD_F")
[ "$MODE" = "744" ] || fail "chmod go+r expected 744 (got $MODE)"

"$BIN/chmod" a=rx "$CHMOD_F" || fail "chmod a=rx failed"
MODE=$(stat -c %a "$CHMOD_F")
[ "$MODE" = "555" ] || fail "chmod a=rx expected 555 (got $MODE)"

"$BIN/chmod" u=rw,go=r "$CHMOD_F" || fail "chmod u=rw,go=r failed"
MODE=$(stat -c %a "$CHMOD_F")
[ "$MODE" = "644" ] || fail "chmod u=rw,go=r expected 644 (got $MODE)"

mark "after-chmod"

# --- chown: numeric uid[:gid] (non-root expected to fail) ---
CHOWN_F="$TMP/chown-file"
printf 'y' >"$CHOWN_F"
set +e
"$BIN/chown" 0 "$CHOWN_F" >"$TMP/out" 2>"$TMP/err"
RC=$?
set -e
[ $RC -ne 0 ] || fail "chown unexpectedly succeeded (are tests running as root?)"
[ -s "$TMP/err" ] || fail "chown should print an error when it fails"

mark "after-chown"

# --- printf: minimal format substitutions ---
OUT=$($BIN/printf '%s %d\n' hi 3)
[ "$OUT" = "hi 3" ] || fail "printf %s %d unexpected output: '$OUT'"

OUT=$($BIN/printf '%u %x %c\n' 10 255 Z)
[ "$OUT" = "10 ff Z" ] || fail "printf %u %x %c unexpected output: '$OUT'"

OUT=$($BIN/printf 'a\tb\nX')
EXP=$(printf 'a\tb\nX')
[ "$OUT" = "$EXP" ] || fail "printf escapes unexpected output: '$OUT'"

OUT=$($BIN/printf '\\X')
[ "$OUT" = "\\X" ] || fail "printf \\\\ unexpected output: '$OUT'"

OUT=$($BIN/printf '%d:%u:%x:%s:Z\n')
[ "$OUT" = "0:0:0::Z" ] || fail "printf missing args unexpected output: '$OUT'"

OUT=$($BIN/printf 'end\\')
[ "$OUT" = "end\\" ] || fail "printf trailing backslash unexpected output: '$OUT'"

set +e
$BIN/printf '%d\n' notanumber >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "printf should usage-error on invalid number (got $RC)"

OUT=$($BIN/printf '%%\n')
[ "$OUT" = "%" ] || fail "printf %% unexpected output: '$OUT'"

mark "after-printf"

# --- yes: repeat lines (bounded by head) ---
OUT=$($BIN/yes x | $BIN/head -n 3)
[ "$OUT" = "x
x
x" ] || fail "yes unexpected output"

mark "after-yes"

# --- xargs: build command lines from stdin ---
OUT=$(printf 'a b\nc\t d\n' | $BIN/xargs $BIN/echo)
[ "$OUT" = "a b c d" ] || fail "xargs basic unexpected output: '$OUT'"

OUT=$(printf '1 2 3\n' | $BIN/xargs -n 2 $BIN/echo)
[ "$OUT" = "1 2
3" ] || fail "xargs -n 2 unexpected output: '$OUT'"

OUT=$(printf '' | $BIN/xargs $BIN/echo hi)
[ "$OUT" = "" ] || fail "xargs should do nothing on empty input: '$OUT'"

OUT=$(printf 'a b\n' | $BIN/xargs -I {} -- $BIN/echo pre-{}-post)
[ "$OUT" = "pre-a-post
pre-b-post" ] || fail "xargs -I replacement unexpected: '$OUT'"

OUT=$(printf 'x\n' | $BIN/xargs -I {} -- $BIN/echo hi)
[ "$OUT" = "hi x" ] || fail "xargs -I should append token if no placeholder used: '$OUT'"

set +e
$BIN/xargs >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "xargs should usage-error with no CMD (got $RC)"

# --- seq: integer sequences ---
mark "seq"
OUT=$($BIN/seq 3)
[ "$OUT" = "1
2
3" ] || fail "seq 3 unexpected"

OUT=$($BIN/seq 2 4)
[ "$OUT" = "2
3
4" ] || fail "seq 2 4 unexpected"

OUT=$($BIN/seq 5 -2 1)
[ "$OUT" = "5
3
1" ] || fail "seq 5 -2 1 unexpected"

OUT=$($BIN/seq -3 -1)
[ "$OUT" = "-3
-2
-1" ] || fail "seq -3 -1 unexpected"

OUT=$($BIN/seq 1 1 1000 | $BIN/wc -l)
[ "$OUT" = "1000" ] || fail "seq 1 1 1000 line count unexpected: '$OUT'"

set +e
$BIN/seq 1 0 2 >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "seq should usage-error on zero increment (got $RC)"

mark "after-seq"

# --- uname: sysname ---
mark "uname"
OUT=$($BIN/uname)
[ "$OUT" = "Linux" ] || fail "uname unexpected output: '$OUT'"

# --- hostname: nodename from uname ---
mark "hostname"
OUT=$($BIN/hostname)
[ "$OUT" = "$(uname -n)" ] || fail "hostname unexpected output: '$OUT'"

# --- nproc: online CPUs as seen by sched affinity ---
mark "nproc"
if command -v nproc >/dev/null 2>&1; then
  EXP=$(nproc)
else
  EXP=$(getconf _NPROCESSORS_ONLN)
fi
OUT=$($BIN/nproc)
[ "$OUT" = "$EXP" ] || fail "nproc unexpected output: '$OUT' (exp '$EXP')"

# --- clear: ANSI clear+home sequence ---
mark "clear"
OUT=$($BIN/clear)
EXP=$(printf '\033[H\033[2J')
[ "$OUT" = "$EXP" ] || fail "clear unexpected output"

# --- uptime/free/mount: basic output exists ---
mark "uptime/free/mount"
OUT=$($BIN/uptime)
case "$OUT" in
  "up "*) : ;;
  *) fail "uptime should start with 'up ' (got '$OUT')" ;;
esac

OUT=$($BIN/free)
OUT1=$(printf '%s\n' "$OUT" | $BIN/head -n 1)
OUT2=$(printf '%s\n' "$OUT" | $BIN/head -n 2 | $BIN/tail -n 1)
case "$OUT1" in
  mem[[:space:]]*) : ;;
  *) fail "free should start with 'mem' + whitespace (got '$OUT')" ;;
esac
case "$OUT2" in
  swap[[:space:]]*) : ;;
  *) fail "free should include swap line (got '$OUT')" ;;
esac

OUT=$($BIN/mount | $BIN/head -n 1)
[ -n "$OUT" ] || fail "mount should print at least one line"

# --- strings: extracts printable runs ---
mark "strings"
STRF="$TMP/strings_in"
printf 'xx\0hello\0yy' >"$STRF"
OUT=$($BIN/strings "$STRF")
[ "$OUT" = "hello" ] || fail "strings unexpected output: '$OUT'"

OUT=$($BIN/strings -n 3 "$STRF")
[ "$OUT" = "hello" ] || fail "strings -n unexpected output: '$OUT'"

set +e
$BIN/strings -n 0 "$STRF" >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "strings -n 0 should be usage error (got $RC)"

# --- rev: reverse bytes per line ---
mark "rev"
OUT=$(printf 'abc\n123\n' | $BIN/rev)
EXP=$(printf 'cba\n321')
[ "$OUT" = "$EXP" ] || fail "rev unexpected output: '$OUT'"

# --- column: align whitespace-delimited fields ---
mark "column"
OUT=$(printf 'a bb\nccc d\n' | $BIN/column)
# Expect stable alignment (at least one space between columns).
printf '%s' "$OUT" | grep -Eq '^a +bb$' || fail "column line1 unexpected: '$OUT'"
printf '%s' "$OUT" | grep -Eq '^ccc +d$' || fail "column line2 unexpected: '$OUT'"

# --- col: handle backspace and carriage return ---
mark "col"
OUT=$(printf 'ab\bc\n' | $BIN/col)
[ "$OUT" = "ac" ] || fail "col backspace unexpected: '$OUT'"
OUT=$(printf 'hello\rY\n' | $BIN/col)
[ "$OUT" = "Yello" ] || fail "col carriage return unexpected: '$OUT'"

# --- hexdump: stable line format (basic) ---
mark "hexdump"
HX="$TMP/hexdump_in"
printf 'ABC' >"$HX"
OUT=$($BIN/hexdump "$HX" | $BIN/head -n 1)
printf '%s' "$OUT" | $BIN/grep -q '41 42 43' || fail "hexdump should contain hex bytes (got '$OUT')"
printf '%s' "$OUT" | $BIN/grep -q '|ABC' || fail "hexdump should contain ASCII gutter (got '$OUT')"

# --- env: print environment and execute with modified env ---
mark "env"
$BIN/env | grep -q '^PATH=' || fail "env output missing PATH= entry"

OUT=$($BIN/env -i)
[ "$OUT" = "" ] || fail "env -i should print nothing"

$BIN/env FOO=bar | grep -q '^FOO=bar$' || fail "env FOO=bar should include assignment"

OUT=$($BIN/env -i FOO=bar)
[ "$OUT" = "FOO=bar" ] || fail "env -i FOO=bar unexpected output: '$OUT'"

OUT=$($BIN/env -i FOO=bar -u FOO)
[ "$OUT" = "" ] || fail "env -u should remove var (expected empty): '$OUT'"

# env -0: NUL-separated output (verify via byte count)
OUT=$($BIN/env -i FOO=bar -0 | $BIN/wc -c)
[ "$OUT" = "8" ] || fail "env -0 byte count unexpected (expected 8): '$OUT'"

OUT=$($BIN/env -i FOO=bar $BIN/env)
[ "$OUT" = "FOO=bar" ] || fail "env exec (self) unexpected output: '$OUT'"

OUT=$($BIN/env -i FOO=bar -u FOO $BIN/env)
[ "$OUT" = "" ] || fail "env exec with -u unexpected output: '$OUT'"

OUT=$($BIN/env -i FOO=bar $BIN/echo hi)
[ "$OUT" = "hi" ] || fail "env exec with absolute CMD failed: '$OUT'"

# --- sh: minimal shell for pipelines + redirects ---
mark "sh"
OUT=$($BIN/sh -c "$BIN/echo hi")
[ "$OUT" = "hi" ] || fail "sh -c echo failed: '$OUT'"

OUT=$($BIN/sh -c "$BIN/echo hi | $BIN/tr i o")
[ "$OUT" = "ho" ] || fail "sh pipeline failed: '$OUT'"

$BIN/sh -c "$BIN/echo hi > $TMP/sh_out" || fail "sh redirect > failed"
[ "$(cat "$TMP/sh_out")" = "hi" ] || fail "sh redirect file content mismatch"

$BIN/sh -c "$BIN/echo one > $TMP/sh_app; $BIN/echo two >> $TMP/sh_app" || fail "sh redirect >> failed"
[ "$(cat "$TMP/sh_app")" = "one
two" ] || fail "sh >> file content mismatch"

OUT=$($BIN/sh -c "$BIN/cat < $TMP/sh_app | $BIN/wc -l")
[ "$OUT" = "2" ] || fail "sh redirect < / pipeline failed: '$OUT'"

# --- sed: minimal subset ---
mark "sed"
OUT=$(printf 'foo\n' | $BIN/sed 's/o/a/')
[ "$OUT" = "fao" ] || fail "sed s/// unexpected: '$OUT'"

OUT=$(printf 'foo\n' | $BIN/sed 's/o/a/g')
[ "$OUT" = "faa" ] || fail "sed s///g unexpected: '$OUT'"

OUT=$(printf 'abc\n' | $BIN/sed 's/^a/A/' | $BIN/sed 's/c$/C/')
[ "$OUT" = "AbC" ] || fail "sed anchors unexpected: '$OUT'"

OUT=$(printf 'abc\n' | $BIN/sed 's/.*/X/')
[ "$OUT" = "X" ] || fail "sed dotstar unexpected: '$OUT'"

OUT=$(printf 'foo\nbar\n' | $BIN/sed -n 's/o/O/p')
[ "$OUT" = "fOo" ] || fail "sed -n ...p unexpected: '$OUT'"

SED_F="$TMP/sed_in"
printf 'hello\n' >"$SED_F"
OUT=$($BIN/sed 's/ello/OLA/' "$SED_F")
[ "$OUT" = "hOLA" ] || fail "sed file unexpected: '$OUT'"

# capture groups (BRE-ish: \( ... \) and \1)
OUT=$(printf 'abc\n' | $BIN/sed 's/^\(a.*\)$/X\1Y/')
[ "$OUT" = "XabcY" ] || fail "sed capture group unexpected: '$OUT'"

# address ranges
OUT=$(printf 'a\nb\nc\nd\n' | $BIN/sed '2,3s/.*/X/')
[ "$OUT" = "a
X
X
d" ] || fail "sed address range unexpected: '$OUT'"

# hold space: copy first line into hold, then replace second line with it
OUT=$(printf 'a\nb\n' | $BIN/sed -e '1h' -e '2g')
[ "$OUT" = "a
a" ] || fail "sed hold space unexpected: '$OUT'"

# --- awk: minimal subset (print/fields/pattern) ---
mark "awk"
OUT=$(printf 'a b\nc d\n' | $BIN/awk '{print $2}')
[ "$OUT" = "b
d" ] || fail "awk {print $2} unexpected: '$OUT'"

OUT=$(printf 'a:b::d\n' | $BIN/awk -F : '{print $3}')
[ "$OUT" = "" ] || fail "awk -F : field 3 (empty) unexpected: '$OUT'"

OUT=$(printf 'ax 1\nbx 2\n' | $BIN/awk '/^a/ {print $1}')
[ "$OUT" = "ax" ] || fail "awk pattern unexpected: '$OUT'"

OUT=$(printf 'a b\nc\n' | $BIN/awk '{print NR,NF}')
[ "$OUT" = "1 2
2 1" ] || fail "awk NR,NF unexpected: '$OUT'"

OUT=$(printf 'x\n' | $BIN/awk '{print "X",$1}')
[ "$OUT" = "X x" ] || fail "awk string literal unexpected: '$OUT'"

OUT=$(printf 'a 9\nb 10\nc 11\n' | $BIN/awk '$2>10 {print $1}')
[ "$OUT" = "c" ] || fail "awk numeric pattern ($2>10) unexpected: '$OUT'"

OUT=$(printf 'a 10\nb 10\n' | $BIN/awk '$2==10 {print NR}')
[ "$OUT" = "1
2" ] || fail "awk numeric pattern (==) unexpected: '$OUT'"

# --- find: minimal subset ---
mark "find"
FROOT="$TMP/find_root"
mkdir -p "$FROOT/sub"
printf x >"$FROOT/a"
printf y >"$FROOT/sub/b"
ln -s "sub" "$FROOT/linksub"

# -type f (order not guaranteed; sort for determinism)
OUT=$($BIN/find "$FROOT" -type f | $BIN/sort)
EXP=$(printf '%s\n%s\n' "$FROOT/a" "$FROOT/sub/b")
[ "$OUT" = "$EXP" ] || fail "find -type f unexpected: '$OUT'"

# -name with glob
OUT=$($BIN/find "$FROOT" -name 'b' -type f)
[ "$OUT" = "$FROOT/sub/b" ] || fail "find -name b unexpected: '$OUT'"

OUT=$($BIN/find "$FROOT" -name 'a*' -type f)
[ "$OUT" = "$FROOT/a" ] || fail "find -name a* unexpected: '$OUT'"

# -maxdepth 0 should print only the root operand
OUT=$($BIN/find "$FROOT" -maxdepth 0)
[ "$OUT" = "$FROOT" ] || fail "find -maxdepth 0 unexpected: '$OUT'"

# -mindepth 1 should omit the root
OUT=$($BIN/find "$FROOT" -mindepth 1 -maxdepth 1 | $BIN/sort)
EXP=$(printf '%s\n%s\n%s\n' "$FROOT/a" "$FROOT/linksub" "$FROOT/sub")
[ "$OUT" = "$EXP" ] || fail "find -mindepth 1 -maxdepth 1 unexpected: '$OUT'"

# --- stat: size/perm output ---
mark "stat"
STAT_F="$TMP/stat-file"
printf 'abc' >"$STAT_F"
$BIN/chmod 600 "$STAT_F" || fail "chmod for stat test failed"
OUT=$($BIN/stat "$STAT_F")
case "$OUT" in
  (*"perm=600"*"size=3"*) : ;;
  (*) fail "stat output missing perm/size: '$OUT'" ;;
esac

STAT_DIR="$TMP/stat-dir"
mkdir -p "$STAT_DIR"
OUT=$($BIN/stat "$STAT_DIR")
case "$OUT" in
  (*"type=dir"*) : ;;
  (*) fail "stat dir should report type=dir: '$OUT'" ;;
esac

ln -s "$STAT_F" "$TMP/stat-link"
OUT=$($BIN/stat "$TMP/stat-link")
case "$OUT" in
  (*"type=reg"*"size=3"*) : ;;
  (*) fail "stat symlink should follow and report regular file: '$OUT'" ;;
esac

LNKLEN=$(stat -c %s "$TMP/stat-link")
OUT=$($BIN/stat -l "$TMP/stat-link")
case "$OUT" in
  (*"type=lnk"*"size=$LNKLEN"*) : ;;
  (*) fail "stat -l should lstat and report symlink: '$OUT'" ;;
esac

if command -v mkfifo >/dev/null 2>&1; then
  mkfifo "$TMP/stat-fifo"
  OUT=$($BIN/stat "$TMP/stat-fifo")
  case "$OUT" in
    (*"type=other"*) : ;;
    (*) fail "stat fifo should report type=other: '$OUT'" ;;
  esac
fi

# --- df: basic output exists and includes path ---
mark "df"
OUT=$($BIN/df "$TMP")
set -- $OUT
[ "$1" = "$TMP" ] || fail "df did not echo path as first field: '$OUT'"
case "$2" in (""|*[!0-9]*) fail "df total not numeric: '$OUT'" ;; esac
case "$3" in (""|*[!0-9]*) fail "df used not numeric: '$OUT'" ;; esac
case "$4" in (""|*[!0-9]*) fail "df avail not numeric: '$OUT'" ;; esac

OUT=$($BIN/df)
set -- $OUT
[ "$1" = "." ] || fail "df default operand should be '.': '$OUT'"
case "$2" in (""|*[!0-9]*) fail "df(.) total not numeric: '$OUT'" ;; esac
case "$3" in (""|*[!0-9]*) fail "df(.) used not numeric: '$OUT'" ;; esac
case "$4" in (""|*[!0-9]*) fail "df(.) avail not numeric: '$OUT'" ;; esac

OUT=$($BIN/df -h "$TMP")
set -- $OUT
[ "$1" = "$TMP" ] || fail "df -h did not echo path as first field: '$OUT'"
case "$2" in ([0-9]*|[0-9]*[KMGTP]) : ;; (*) fail "df -h total not human-ish: '$OUT'" ;; esac
case "$3" in ([0-9]*|[0-9]*[KMGTP]) : ;; (*) fail "df -h used not human-ish: '$OUT'" ;; esac
case "$4" in ([0-9]*|[0-9]*[KMGTP]) : ;; (*) fail "df -h avail not human-ish: '$OUT'" ;; esac

OUT=$($BIN/df -T "$TMP")
set -- $OUT
[ "$1" = "$TMP" ] || fail "df -T did not echo path as first field: '$OUT'"
T5=$5
case "$T5" in
  0x*) T5=${T5#0x} ;;
esac
case "$T5" in (""|*[!0-9a-fA-F]*) fail "df -T type not hex: '$OUT'" ;; esac

OUT=$($BIN/df -H "$TMP" | $BIN/head -n 1)
case "$OUT" in
  path*total*used*avail) : ;;
  *) fail "df -H header unexpected: '$OUT'" ;;
esac

set +e
$BIN/df "$TMP/does-not-exist" >"$TMP/out" 2>"$TMP/err"
RC=$?
set -e
[ $RC -eq 1 ] || fail "df should exit 1 on missing path (got $RC)"
[ -s "$TMP/err" ] || fail "df should print an error on missing path"

mark "after-df"

# --- du: directory traversal and -s summary ---
mark "du"
DUDIR="$TMP/du"
mkdir -p "$DUDIR/sub"
printf 'abc' >"$DUDIR/a"
printf 'hello' >"$DUDIR/sub/b"

S1=$(stat -c %s "$DUDIR/a")
S2=$(stat -c %s "$DUDIR/sub/b")
SUB=$((S2))
TOTAL=$((S1 + S2))

OUT=$($BIN/du "$DUDIR")
EXP=$(printf '%s\t%s\n%s\t%s\n' "$SUB" "$DUDIR/sub" "$TOTAL" "$DUDIR")
[ "$OUT" = "$EXP" ] || fail "du dir unexpected output: '$OUT'"

OUT=$($BIN/du -s "$DUDIR")
EXP=$(printf '%s\t%s\n' "$TOTAL" "$DUDIR")
[ "$OUT" = "$EXP" ] || fail "du -s unexpected output: '$OUT'"

# --- du: does not follow symlinks (including loops) ---
mark "du symlink"
DULOOP="$TMP/du_loop"
mkdir -p "$DULOOP"
ln -s . "$DULOOP/loop"
OUT=$($BIN/du "$DULOOP")
EXP=$(printf '1\t%s\n' "$DULOOP")
[ "$OUT" = "$EXP" ] || fail "du symlink loop unexpected output: '$OUT'"

# --- du: permission denied should fail (exit 1) and print an error ---
mark "du permission"
DUPERM="$TMP/du_perm"
mkdir -p "$DUPERM/secret"
printf 'x' >"$DUPERM/secret/file"
chmod 000 "$DUPERM/secret"

set +e
$BIN/du -s "$DUPERM/secret" >"$TMP/out" 2>"$TMP/err"
RC=$?
set -e

# Restore permissions so cleanup can remove it.
chmod 700 "$DUPERM/secret"

[ $RC -eq 1 ] || fail "du should exit 1 on permission denied (got $RC)"
[ -s "$TMP/err" ] || fail "du should print an error on permission denied"

# --- test / [: condition evaluation ---
TEST_DIR="$TMP/test_tool"
mkdir -p "$TEST_DIR/dir"
printf 'x' >"$TEST_DIR/file"

$BIN/test -e "$TEST_DIR/file" || fail "test -e existing should be true"
set +e
$BIN/test -e "$TEST_DIR/missing" >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 1 ] || fail "test -e missing should be false (got $RC)"

$BIN/test -f "$TEST_DIR/file" || fail "test -f file should be true"
set +e
$BIN/test -f "$TEST_DIR/dir" >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 1 ] || fail "test -f dir should be false (got $RC)"

$BIN/test -d "$TEST_DIR/dir" || fail "test -d dir should be true"

$BIN/test -z "" || fail "test -z empty should be true"
set +e
$BIN/test -n "" >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 1 ] || fail "test -n empty should be false (got $RC)"
$BIN/test -n "hi" || fail "test -n non-empty should be true"

$BIN/test a = a || fail "test string '=' should be true"
$BIN/test a != b || fail "test string '!=' should be true"

$BIN/test 2 -eq 2 || fail "test -eq should be true"
$BIN/test 2 -lt 3 || fail "test -lt should be true"

"$BIN/[" -f "$TEST_DIR/file" "]" || fail "[ -f file ] should be true"
set +e
"$BIN/[" -f "$TEST_DIR/file" >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "[ missing closing ] should be usage error (got $RC)"

# --- grep: regex pattern matching ---
GREP_F="$TMP/grep_file"
printf 'a\nFoo\nbar\nFOO\n' >"$GREP_F"

OUT=$($BIN/grep Foo "$GREP_F")
[ "$OUT" = "Foo" ] || fail "grep basic match unexpected: '$OUT'"

OUT=$($BIN/grep -i foo "$GREP_F")
[ "$OUT" = "Foo
FOO" ] || fail "grep -i unexpected: '$OUT'"

OUT=$($BIN/grep -v bar "$GREP_F")
[ "$OUT" = "a
Foo
FOO" ] || fail "grep -v unexpected: '$OUT'"

OUT=$($BIN/grep -c -i foo "$GREP_F")
[ "$OUT" = "2" ] || fail "grep -c unexpected: '$OUT'"
OUT=$($BIN/grep -n -i foo "$GREP_F")
[ "$OUT" = "2:Foo
4:FOO" ] || fail "grep -n unexpected: '$OUT'"

OUT=$(printf 'xx\nneedle\nyy\n' | $BIN/grep needle)
[ "$OUT" = "needle" ] || fail "grep stdin unexpected: '$OUT'"

OUT=$($BIN/grep '^Fo.$' "$GREP_F")
[ "$OUT" = "Foo" ] || fail "grep regex anchors/dot unexpected: '$OUT'"

GREP_F2="$TMP/grep_file2"
printf 'a.b\nab\n' >"$GREP_F2"
OUT=$($BIN/grep -F '.' "$GREP_F2")
[ "$OUT" = "a.b" ] || fail "grep -F fixed-string unexpected: '$OUT'"

set +e
$BIN/grep -q needle "$GREP_F" >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 1 ] || fail "grep -q should be 1 when no match (got $RC)"

set +e
$BIN/grep -q -i foo "$GREP_F" >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 0 ] || fail "grep -q should be 0 when match exists (got $RC)"

# --- ls: -l long format and -h human size ---
LSDIR="$TMP/ls_long"
mkdir -p "$LSDIR"
printf 'x' > "$LSDIR/f"
mkdir -p "$LSDIR/sub"
printf 'h' > "$LSDIR/.hidden"
ln -s "f" "$LSDIR/link"

$BIN/ls -l "$LSDIR" | grep -q " f$" || fail "ls -l missing file name"
$BIN/ls -l "$LSDIR" | grep -q "^-" || fail "ls -l did not print long format"
$BIN/ls -l "$LSDIR" | grep -q "^l" || fail "ls -l did not show symlink type"
$BIN/ls -l "$LSDIR" | grep -q " link$" || fail "ls -l missing symlink name"

$BIN/ls "$LSDIR" | grep -q "^\\.hidden$" && fail "ls should hide dotfiles by default"
$BIN/ls -a "$LSDIR" | grep -q "^\\.hidden$" || fail "ls -a missing dotfile"
$BIN/ls -a "$LSDIR" | grep -q "^\\.$" || fail "ls -a missing '.'"
$BIN/ls -a "$LSDIR" | grep -q "^\\.\\.$" || fail "ls -a missing '..'"

# -h without -l should be accepted (no effect)
$BIN/ls -h "$LSDIR" >/dev/null 2>&1 || fail "ls -h should succeed"

# combined flags
$BIN/ls -alh "$LSDIR" | grep -q " \\.hidden$" || fail "ls -alh missing dotfile"

LSFILE="$TMP/ls_file_operand"
printf 'z' >"$LSFILE"
OUT=$($BIN/ls "$LSFILE")
[ "$OUT" = "$LSFILE" ] || fail "ls file operand unexpected: '$OUT'"

set +e
$BIN/ls "$LSDIR" "$LSFILE" >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "ls should usage-error on multiple operands (got $RC)"

dd if=/dev/zero of="$LSDIR/big" bs=1024 count=2 >/dev/null 2>&1
$BIN/ls -lh "$LSDIR" | grep -q " big$" || fail "ls -lh missing big"
$BIN/ls -lh "$LSDIR" | grep -Eq " [0-9]+[KMGT] " || fail "ls -lh missing human size suffix"

# --- ls: -R recursive listing ---
LSR="$TMP/ls_rec"
mkdir -p "$LSR/root/sub"
printf 'r' >"$LSR/root/rfile"
printf 's' >"$LSR/root/sub/sfile"
printf 'h' >"$LSR/root/sub/.hfile"
ln -s "sub" "$LSR/root/linkdir"

OUT=$($BIN/ls -R "$LSR/root")
echo "$OUT" | grep -Fq "$LSR/root:" || fail "ls -R missing root header"
echo "$OUT" | grep -Fq "$LSR/root/sub:" || fail "ls -R missing subdir header"
echo "$OUT" | grep -q "^rfile$" || fail "ls -R missing rfile"
echo "$OUT" | grep -q "^sfile$" || fail "ls -R missing sfile"
echo "$OUT" | grep -q "^\\.hfile$" && fail "ls -R should hide dotfiles by default"
echo "$OUT" | grep -Fq "$LSR/root/linkdir:" && fail "ls -R should not recurse into symlinked dirs"

OUT=$($BIN/ls -aR "$LSR/root")
echo "$OUT" | grep -q "^\\.hfile$" || fail "ls -aR missing hidden file"

exit 0
