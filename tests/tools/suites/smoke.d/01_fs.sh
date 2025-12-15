#!/bin/sh
set -eu

BIN=${1:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}
TMP=${2:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../../lib/testlib.sh"
# --- true/false: exit codes ---
set +e
$BIN/true >/dev/null 2>&1
RC=$?
[ $RC -eq 0 ] || fail "true should exit 0 (got $RC)"

$BIN/false >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 1 ] || fail "false should exit 1 (got $RC)"

# --- pwd: should match shell pwd ---
mark "pwd"
OUT=$($BIN/pwd)
[ "$OUT" = "$(pwd)" ] || fail "pwd mismatch (got '$OUT', exp '$(pwd)')"

# --- echo: basic output and -n ---
OUT=$($BIN/echo hello world)
[ "$OUT" = "hello world" ] || fail "echo basic unexpected: '$OUT'"

OUT=$($BIN/echo -n "no newline")
[ "$OUT" = "no newline" ] || fail "echo -n unexpected: '$OUT'"

OUT=$($BIN/echo -e 'a\nb' | $BIN/wc -l)
[ "$OUT" = "2" ] || fail "echo -e should interpret \\n (got '$OUT')"

OUT=$($BIN/echo -E 'a\nb')
[ "$OUT" = "a\\nb" ] || fail "echo -E should print literal escapes (got '$OUT')"

# --- mv: rename file and directory ---
printf 'x' >"$TMP/mv_src"
$BIN/mv "$TMP/mv_src" "$TMP/mv_dst" || fail "mv file failed"
[ ! -e "$TMP/mv_src" ] || fail "mv did not remove src"
[ "$(cat "$TMP/mv_dst")" = "x" ] || fail "mv did not preserve file contents"

mkdir -p "$TMP/mv_dir_src/sub"
printf 'y' >"$TMP/mv_dir_src/sub/file"
$BIN/mv "$TMP/mv_dir_src" "$TMP/mv_dir_dst" || fail "mv dir failed"
[ ! -e "$TMP/mv_dir_src" ] || fail "mv dir did not remove src"
[ "$(cat "$TMP/mv_dir_dst/sub/file")" = "y" ] || fail "mv dir did not preserve contents"

# --- mkdir: -p creates parents, is idempotent, fails if a path component is a file ---
NEST="$TMP/mkdirp/a/b/c"
"$BIN/mkdir" -p "$NEST" || fail "mkdir -p failed to create nested dirs"
[ -d "$NEST" ] || fail "mkdir -p did not create expected directory"

"$BIN/mkdir" -p "$NEST" || fail "mkdir -p should succeed on existing path"

# --- mkdir: -m sets mode (best-effort; masked by umask) ---
(umask 000; "$BIN/mkdir" -m 700 "$TMP/mkdir_m") || fail "mkdir -m failed"
MODE=$(stat -c %a "$TMP/mkdir_m")
[ "$MODE" = "700" ] || fail "mkdir -m did not set expected mode (got $MODE)"

(umask 000; "$BIN/mkdir" -p -m 711 "$TMP/mkdir_mp/a/b") || fail "mkdir -p -m failed"
MODEA=$(stat -c %a "$TMP/mkdir_mp")
MODEB=$(stat -c %a "$TMP/mkdir_mp/a")
MODEC=$(stat -c %a "$TMP/mkdir_mp/a/b")
[ "$MODEA" = "711" ] || fail "mkdir -p -m did not set expected mode for parent (got $MODEA)"
[ "$MODEB" = "711" ] || fail "mkdir -p -m did not set expected mode for parent (got $MODEB)"
[ "$MODEC" = "711" ] || fail "mkdir -p -m did not set expected mode for leaf (got $MODEC)"

mkdir -p "$TMP/mkdirp2"
printf 'x' >"$TMP/mkdirp2/file"
set +e
"$BIN/mkdir" -p "$TMP/mkdirp2/file/sub" >"$TMP/out" 2>"$TMP/err"
RC=$?
set -e
[ $RC -ne 0 ] || fail "mkdir -p should fail when a path component is a file"
[ -s "$TMP/err" ] || fail "mkdir -p should print an error on failure"

# --- rmdir: -p removes empty ancestors, stops at non-empty parent ---
mkdir -p "$TMP/rmdir_p/empty/a/b"
"$BIN/rmdir" -p "$TMP/rmdir_p/empty/a/b" || fail "rmdir -p failed"
[ ! -e "$TMP/rmdir_p/empty/a/b" ] || fail "rmdir -p did not remove leaf"
[ ! -e "$TMP/rmdir_p/empty/a" ] || fail "rmdir -p did not remove empty parent"

mkdir -p "$TMP/rmdir_p/nonempty/a/b"
printf x >"$TMP/rmdir_p/nonempty/a/keep"
"$BIN/rmdir" -p "$TMP/rmdir_p/nonempty/a/b" || fail "rmdir -p should succeed even if parent is non-empty"
[ ! -e "$TMP/rmdir_p/nonempty/a/b" ] || fail "rmdir -p did not remove leaf under non-empty parent"
[ -d "$TMP/rmdir_p/nonempty/a" ] || fail "rmdir -p should not remove non-empty parent"
[ -f "$TMP/rmdir_p/nonempty/a/keep" ] || fail "rmdir -p should not delete files in parent"

# --- rm: continue on error, still remove what it can ---
mkdir -p "$TMP/rm1"
("$BIN/echo" hi > "$TMP/rm1/good")

set +e
"$BIN/rm" "$TMP/rm1/good" "$TMP/rm1/missing" >"$TMP/out" 2>"$TMP/err"
RC=$?
set -e

[ $RC -eq 1 ] || fail "rm should exit 1 when any operand fails (got $RC)"
[ ! -e "$TMP/rm1/good" ] || fail "rm did not remove existing operand"
[ -s "$TMP/err" ] || fail "rm should print an error for missing operand"

# --- rm: -f ignores missing operands and exits 0 ---
mkdir -p "$TMP/rm_force"
("$BIN/echo" hi > "$TMP/rm_force/good")
"$BIN/rm" -f "$TMP/rm_force/good" "$TMP/rm_force/missing" >"$TMP/out" 2>"$TMP/err" || fail "rm -f should exit 0 when only failures are ENOENT"
[ ! -e "$TMP/rm_force/good" ] || fail "rm -f did not remove existing operand"
[ ! -s "$TMP/err" ] || fail "rm -f should not print an error for missing operand"

# --- rm: -- should allow removing a file named '--' ---
mkdir -p "$TMP/rm2"
("$BIN/echo" x > "$TMP/rm2/--")
"$BIN/rm" -- "$TMP/rm2/--" || fail "rm -- failed to remove file named '--'"
[ ! -e "$TMP/rm2/--" ] || fail "rm -- did not remove file named '--'"

# --- rm: -d removes empty directories (but not non-empty) ---
mkdir -p "$TMP/rm_d/empty"
"$BIN/rm" -d "$TMP/rm_d/empty" || fail "rm -d failed to remove empty directory"
[ ! -e "$TMP/rm_d/empty" ] || fail "rm -d did not remove directory"

mkdir -p "$TMP/rm_d/nonempty"
printf x >"$TMP/rm_d/nonempty/file"
set +e
"$BIN/rm" -d "$TMP/rm_d/nonempty" >"$TMP/out" 2>"$TMP/err"
RC=$?
set -e
[ $RC -eq 1 ] || fail "rm -d should exit 1 on non-empty directory (got $RC)"
[ -s "$TMP/err" ] || fail "rm -d should print an error on failure"
[ -d "$TMP/rm_d/nonempty" ] || fail "rm -d unexpectedly removed non-empty directory"
[ -f "$TMP/rm_d/nonempty/file" ] || fail "rm -d unexpectedly removed file in directory"

# --- rm: -r removes directories recursively and does not follow symlinks ---
mkdir -p "$TMP/rm_r/dir/sub"
printf 'x' >"$TMP/rm_r/dir/sub/file"
"$BIN/rm" -r "$TMP/rm_r/dir" || fail "rm -r failed to remove directory"
[ ! -e "$TMP/rm_r/dir" ] || fail "rm -r did not remove directory"

mkdir -p "$TMP/rm_r2/target/sub"
printf 'y' >"$TMP/rm_r2/target/sub/file"
ln -s "$TMP/rm_r2/target" "$TMP/rm_r2/link"
"$BIN/rm" -r "$TMP/rm_r2/link" || fail "rm -r failed on symlink operand"
[ ! -e "$TMP/rm_r2/link" ] || fail "rm -r should remove symlink itself"
[ -e "$TMP/rm_r2/target/sub/file" ] || fail "rm -r unexpectedly followed symlink into target"

# --- cp: must reject directories (regular files only) ---
mkdir -p "$TMP/cp1/srcdir"
set +e
"$BIN/cp" "$TMP/cp1/srcdir" "$TMP/cp1/dst" >"$TMP/out" 2>"$TMP/err"
RC=$?
set -e
[ $RC -eq 1 ] || fail "cp dir should exit 1 (got $RC)"

# --- cp: -r recursively copies directories ---
mkdir -p "$TMP/cp_r/srcdir/sub"
printf 'hello\n' >"$TMP/cp_r/srcdir/sub/file"
"$BIN/cp" -r "$TMP/cp_r/srcdir" "$TMP/cp_r/dstdir" || fail "cp -r failed"
cmp -s "$TMP/cp_r/srcdir/sub/file" "$TMP/cp_r/dstdir/sub/file" || fail "cp -r did not copy file contents"

# --- cp: -p preserves mode (best-effort) ---
CPPSRC="$TMP/cp_p_src"
CPPDST="$TMP/cp_p_dst"
printf 'x' >"$CPPSRC"
"$BIN/chmod" 640 "$CPPSRC" || fail "chmod for cp -p test failed"
"$BIN/cp" -p "$CPPSRC" "$CPPDST" || fail "cp -p failed"
MODE_SRC=$(stat -c %a "$CPPSRC")
MODE_DST=$(stat -c %a "$CPPDST")
[ "$MODE_SRC" = "$MODE_DST" ] || fail "cp -p did not preserve mode (src $MODE_SRC, dst $MODE_DST)"

