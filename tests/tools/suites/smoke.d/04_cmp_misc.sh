#!/bin/sh
set -eu

BIN=${1:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}
TMP=${2:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../../lib/testlib.sh"
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

# --- diff -u: minimal unified format (first mismatch + context) ---
printf 'a\nb\nc\n' >"$TMP/diff1"
printf 'a\nX\nc\n' >"$TMP/diff2"
set +e
OUT=$("$BIN/diff" -u "$TMP/diff1" "$TMP/diff2")
RC=$?
set -e
[ $RC -eq 1 ] || fail "diff -u different files should exit 1 (got $RC)"
printf '%s' "$OUT" | "$BIN/grep" -q '^--- ' || fail "diff -u should print --- header (got '$OUT')"
printf '%s' "$OUT" | "$BIN/grep" -q '^\+\+\+ ' || fail "diff -u should print +++ header (got '$OUT')"
printf '%s' "$OUT" | "$BIN/grep" -q '^@@ -' || fail "diff -u should print @@ hunk header (got '$OUT')"
printf '%s' "$OUT" | "$BIN/grep" -q '^ a$' || fail "diff -u should include context line (got '$OUT')"
printf '%s' "$OUT" | "$BIN/grep" -q '^-b$' || fail "diff -u should include removed line (got '$OUT')"
printf '%s' "$OUT" | "$BIN/grep" -q '^\+X$' || fail "diff -u should include added line (got '$OUT')"

# --- time: runs command and prints timing to stderr ---
OUT=$("$BIN/time" "$BIN/true" 2>&1)
printf '%s' "$OUT" | "$BIN/grep" -q "real " || fail "time should print 'real ' (got '$OUT')"

# --- ps: prints header and at least one process ---
OUT=$("$BIN/ps" | "$BIN/head" -n 1)
[ "$OUT" = "PID CMD" ] || fail "ps header unexpected (got '$OUT')"
NLINES=$("$BIN/ps" | "$BIN/wc" -l)
[ "$NLINES" -ge 2 ] || fail "ps should list at least one process (got $NLINES lines)"

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

# --- printf: width/precision ---
OUT=$($BIN/printf '%5d\n' 3)
[ "$OUT" = "    3" ] || fail "printf %5d unexpected output: '$OUT'"

OUT=$($BIN/printf '%05d\n' 3)
[ "$OUT" = "00003" ] || fail "printf %05d unexpected output: '$OUT'"

OUT=$($BIN/printf '%-5d\n' 3)
[ "$OUT" = "3    " ] || fail "printf %-5d unexpected output: '$OUT'"

OUT=$($BIN/printf '%.3s\n' abcdef)
[ "$OUT" = "abc" ] || fail "printf %.3s unexpected output: '$OUT'"

OUT=$($BIN/printf '%8.3s\n' abcdef)
[ "$OUT" = "     abc" ] || fail "printf %8.3s unexpected output: '$OUT'"

OUT=$($BIN/printf '%.4x\n' 10)
[ "$OUT" = "000a" ] || fail "printf %.4x unexpected output: '$OUT'"

OUT=$($BIN/printf '%6.4u\n' 12)
[ "$OUT" = "  0012" ] || fail "printf %6.4u unexpected output: '$OUT'"

OUT=$($BIN/printf '%05d\n' -3)
[ "$OUT" = "-0003" ] || fail "printf %05d (neg) unexpected output: '$OUT'"

OUT=$($BIN/printf '%05.3d\n' 7)
[ "$OUT" = "  007" ] || fail "printf %05.3d unexpected output: '$OUT'"

OUT=$($BIN/printf '%.0dZ\n' 0)
[ "$OUT" = "Z" ] || fail "printf %.0d with 0 unexpected output: '$OUT'"

OUT=$($BIN/printf '%-05d\n' 3)
[ "$OUT" = "3    " ] || fail "printf %-05d unexpected output: '$OUT'"

OUT=$($BIN/printf '%-5.3s!\n' abcdef)
[ "$OUT" = "abc  !" ] || fail "printf %-5.3s unexpected output: '$OUT'"

mark "after-printf"

# --- od: octal dump (minimal) ---
ODF="$TMP/od_in"
printf '\0\1\2\377' >"$ODF"
OUT=$($BIN/od "$ODF")
printf '%s' "$OUT" | "$BIN/grep" -q '^0000000' || fail "od should start with octal offset (got '$OUT')"
printf '%s' "$OUT" | "$BIN/grep" -q ' 377' || fail "od should include 377 byte (got '$OUT')"
printf '%s' "$OUT" | "$BIN/grep" -q '^0000004$' || fail "od should print final offset line (got '$OUT')"

OUT=$($BIN/od -An "$ODF")
printf '%s' "$OUT" | "$BIN/grep" -q '^ ' || fail "od -An should start with data (got '$OUT')"
set +e
printf '%s' "$OUT" | "$BIN/grep" -q '^0000000'
RC=$?
set -e
[ $RC -eq 1 ] || fail "od -An should not print addresses (got '$OUT')"

# --- expr: arithmetic and boolean exit codes ---
OUT=$($BIN/expr 1 + 2)
[ "$OUT" = "3" ] || fail "expr 1 + 2 unexpected: '$OUT'"

OUT=$($BIN/expr 2 '*' 3)
[ "$OUT" = "6" ] || fail "expr 2 * 3 unexpected: '$OUT'"

set +e
$BIN/expr 1 = 2 >"$TMP/out" 2>"$TMP/err"
RC=$?
set -e
[ $RC -eq 1 ] || fail "expr 1 = 2 should exit 1 (got $RC)"
[ "$(cat "$TMP/out")" = "0" ] || fail "expr 1 = 2 output unexpected"

OUT=$($BIN/expr foo = foo)
[ "$OUT" = "1" ] || fail "expr foo = foo unexpected: '$OUT'"

OUT=$($BIN/expr 0 '|' 5)
[ "$OUT" = "5" ] || fail "expr 0 | 5 unexpected: '$OUT'"

set +e
$BIN/expr 0 '&' 5 >"$TMP/out" 2>"$TMP/err"
RC=$?
set -e
[ $RC -eq 1 ] || fail "expr 0 & 5 should exit 1 (got $RC)"
[ "$(cat "$TMP/out")" = "0" ] || fail "expr 0 & 5 output unexpected"

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

