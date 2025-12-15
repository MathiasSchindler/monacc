#!/bin/sh
set -eu

BIN=${1:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}
TMP=${2:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../../lib/testlib.sh"
# --- date: epoch seconds (numeric) ---
mark "date/sleep/kill/id/which"
OUT=$($BIN/date)
case "$OUT" in
  (""|*[!0-9]*) fail "date output not numeric: '$OUT'" ;;
esac

# date +FORMAT (UTC, minimal strftime subset)
EPOCH=$($BIN/date)
OUT=$($BIN/date +%s)
[ "$OUT" = "$EPOCH" ] || fail "date +%s should match date epoch (got '$OUT', exp '$EPOCH')"

OUT=$($BIN/date +%Y%m%d%H%M%S)
case "$OUT" in
  (??????????????) : ;;
  (*) fail "date +%Y%m%d%H%M%S should be 14 chars (got '$OUT')" ;;
esac
case "$OUT" in
  (*[!0-9]*) fail "date +%Y%m%d%H%M%S not numeric: '$OUT'" ;;
esac

# --- sleep: integer seconds ---
$BIN/sleep 0 || fail "sleep 0 failed"

# fractional seconds
$BIN/sleep 0.01 || fail "sleep 0.01 failed"
$BIN/sleep .001 || fail "sleep .001 failed"
$BIN/sleep 0.000000001 || fail "sleep 0.000000001 failed"
$BIN/sleep 0. || fail "sleep 0. failed"

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

set +e
$BIN/sleep 1..2 >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "sleep should usage-error on invalid float (got $RC)"

set +e
$BIN/sleep -1 >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "sleep should usage-error on negative seconds (got $RC)"

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

