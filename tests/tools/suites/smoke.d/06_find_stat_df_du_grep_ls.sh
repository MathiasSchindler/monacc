#!/bin/sh
set -eu

BIN=${1:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}
TMP=${2:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../../lib/testlib.sh"
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

# -exec runs a command per match; {} expands to the current path.
# Use PATH=$BIN so the executed command resolves to sysbox tools.
OUT=$(PATH="$BIN" "$BIN/find" "$FROOT" -type f -exec echo {} \; | "$BIN/sort")
EXP=$(printf '%s\n%s\n' "$FROOT/a" "$FROOT/sub/b")
[ "$OUT" = "$EXP" ] || fail "find -exec unexpected: '$OUT'"

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

# sorting (default listing is name-sorted)
LSSORT="$TMP/ls_sort"
mkdir -p "$LSSORT"
printf x >"$LSSORT/z"
printf x >"$LSSORT/a"
printf x >"$LSSORT/m"
OUT=$($BIN/ls "$LSSORT")
EXP=$(printf 'a\nm\nz')
[ "$OUT" = "$EXP" ] || fail "ls should sort by name (got '$OUT')"

OUT=$($BIN/ls -a "$LSSORT")
EXP=$(printf '.\n..\na\nm\nz')
[ "$OUT" = "$EXP" ] || fail "ls -a should sort by name (got '$OUT')"

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
printf '%s\n' "$OUT" | grep -Fq "$LSR/root:" || fail "ls -R missing root header"
printf '%s\n' "$OUT" | grep -Fq "$LSR/root/sub:" || fail "ls -R missing subdir header"
printf '%s\n' "$OUT" | grep -q "^rfile$" || fail "ls -R missing rfile"
printf '%s\n' "$OUT" | grep -q "^sfile$" || fail "ls -R missing sfile"
printf '%s\n' "$OUT" | grep -q "^\\.hfile$" && fail "ls -R should hide dotfiles by default"
printf '%s\n' "$OUT" | grep -Fq "$LSR/root/linkdir:" && fail "ls -R should not recurse into symlinked dirs"

# -R traversal order is name-sorted per directory
mkdir -p "$LSR/root/bdir" "$LSR/root/adir"
printf 'a' >"$LSR/root/adir/afile"
printf 'b' >"$LSR/root/bdir/bfile"
OUT=$($BIN/ls -R "$LSR/root")
LN_A=$(printf '%s\n' "$OUT" | grep -n -F "$LSR/root/adir:" | cut -d: -f1)
LN_B=$(printf '%s\n' "$OUT" | grep -n -F "$LSR/root/bdir:" | cut -d: -f1)
[ -n "$LN_A" ] || fail "ls -R missing adir header"
[ -n "$LN_B" ] || fail "ls -R missing bdir header"
[ "$LN_A" -lt "$LN_B" ] || fail "ls -R should visit adir before bdir (got adir@$LN_A bdir@$LN_B)"

OUT=$($BIN/ls -aR "$LSR/root")
printf '%s\n' "$OUT" | grep -q "^\\.hfile$" || fail "ls -aR missing hidden file"

exit 0
