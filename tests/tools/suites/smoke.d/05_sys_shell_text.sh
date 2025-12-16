#!/bin/sh
set -eu

BIN=${1:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}
TMP=${2:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../../lib/testlib.sh"
# --- uname: sysname ---
mark "uname"
OUT=$($BIN/uname)
[ "$OUT" = "Linux" ] || fail "uname unexpected output: '$OUT'"

OUT=$($BIN/uname -m)
[ "$OUT" = "$(uname -m)" ] || fail "uname -m unexpected output: '$OUT'"

OUT=$($BIN/uname -a)
case "$OUT" in
  (Linux\ *) : ;;
  (*) fail "uname -a should start with 'Linux ' (got '$OUT')" ;;
esac

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

OUT=$($BIN/sh -c "$BIN/echo one; $BIN/echo two")
[ "$OUT" = "one
two" ] || fail "sh ';' sequencing failed: '$OUT'"

set +e
$BIN/sh -c "$BIN/false" >/dev/null 2>&1
RC=$?
set -e
[ $RC -ne 0 ] || fail "sh exit status propagation failed (expected non-zero)"

OUT=$($BIN/sh -c "$BIN/echo \$0:\$1" ARG0 ARG1)
[ "$OUT" = "ARG0:ARG1" ] || fail "sh -c argv ($0/$1) handling failed: '$OUT'"

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

