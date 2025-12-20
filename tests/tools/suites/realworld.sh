#!/bin/sh
set -eu

BIN=${1:?usage: realworld.sh /path/to/sysbox/bin /path/to/tmpdir /path/to/tests/data}
TMP=${2:?usage: realworld.sh /path/to/sysbox/bin /path/to/tmpdir /path/to/tests/data}
DATA=${3:?usage: realworld.sh /path/to/sysbox/bin /path/to/tmpdir /path/to/tests/data}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../lib/testlib.sh"

# Backwards-compatible skip knob.
if [ "${SB_TEST_NO_REALWORLD:-0}" = "1" ] || [ "${SB_TEST_NO_RECIPES:-0}" = "1" ]; then
  if [ "$COUNT_ONLY" = "1" ]; then
    echo 0
  fi
  exit 0
fi

if [ "$VERBOSE" = "1" ]; then
  echo "=== sysbox recipes ===" >&2
  echo "BIN=$BIN" >&2
  echo "TMP=$TMP" >&2
  echo "DATA=$DATA" >&2
fi

# Create per-suite workspace using sysbox tools (not host mkdir/rm).
RROOT="$TMP/recipes"
"$BIN/rm" -r -f "$RROOT" >/dev/null 2>&1 || true
"$BIN/mkdir" -p "$RROOT"

# 1) Word frequency (common: sort | uniq -c | sort -n)
OUT=$(run_box "cat '$DATA/words.txt' | sort | uniq -c | sort -n -r | head -n 2")
EXP=$(printf '4 apple\n3 banana')
assert_eq "word frequency top2" "$EXP" "$OUT"

# 2) Align a whitespace table (column)
OUT=$(run_box "column '$DATA/table.txt'")
EXP=$(printf 'a   bb\nccc d')
assert_eq "column alignment" "$EXP" "$OUT"

# 3) Filter+transform log lines (sed -n + s///p)
OUT=$(run_box "sed -n -e 's/ERROR/WARN/p' '$DATA/log.txt'")
EXP=$(printf 'WARN disk full\nWARN network down')
assert_eq "sed substitution+print" "$EXP" "$OUT"

# 3b) sed: multiple -e, line addressing, and delete
OUT=$(run_box "cat '$DATA/log.txt' | sed -e '2d' -e 's/INFO/DBG/'")
EXP=$(printf 'DBG start\nDBG retry\nERROR network down\nDBG end')
assert_eq "sed -e* + addressing + d" "$EXP" "$OUT"

# 4) Find a tree, sort results, count them (find | sort | wc)
OUT=$(run_box "rm -r -f '$RROOT/tree'; mkdir -p '$RROOT/tree/a'; mkdir -p '$RROOT/tree/b'; echo hi > '$RROOT/tree/a/f1'; echo hi > '$RROOT/tree/a/f2'; echo yo > '$RROOT/tree/b/f3'; find '$RROOT/tree' -type f | sort | wc -l")
assert_eq "find|sort|wc" "3" "$OUT"

# 5) Pipeline with a deliberate failure (ensure rc propagation from the last command)
run_box_rc "echo ok | false"
assert_rc "pipeline exit code propagation" 1 "$RC"

# 5b) sh: && and || short-circuit
OUT=$(run_box "false && echo NO; true || echo NO; false || echo yes")
assert_eq "sh &&/||" "yes" "$OUT"

# 6) Diff as a config change detector (exit code only)
run_box_rc "cp '$DATA/config_a.txt' '$RROOT/a'; cp '$DATA/config_b.txt' '$RROOT/b'; diff '$RROOT/a' '$RROOT/b' >/dev/null"
assert_rc "diff detects changes" 1 "$RC"

# 6b) Parse simple key=value config with grep + cut -d
OUT=$(run_box "grep '^mode=' '$DATA/config_a.txt' | cut -d = -f 2")
assert_eq "config parse (a)" "dev" "$OUT"
OUT=$(run_box "grep '^mode=' '$DATA/config_b.txt' | cut -d = -f 2")
assert_eq "config parse (b)" "prod" "$OUT"

# 7) Round-trip transformation (rev twice)
OUT=$(run_box "cat '$DATA/sentences.txt' | rev | rev")
EXP=$($BIN/cat "$DATA/sentences.txt")
assert_eq "rev round-trip" "$EXP" "$OUT"

# 8) Basic hexdump sanity (extract stable fields with sed)
OUT=$(run_box "echo -n abc > '$RROOT/abc'; hexdump '$RROOT/abc' | sed -e 's/ .*//'")
assert_eq "hexdump offset" "0000000000000000" "$OUT"

OUT=$(run_box "echo -n abc > '$RROOT/abc'; hexdump '$RROOT/abc' | grep '|abc'")
assert_nonempty "hexdump ascii gutter contains abc" "$OUT"

# 9) grep: -q and -v
run_box_rc "grep -q ERROR '$DATA/log.txt'"
assert_rc "grep -q found" 0 "$RC"
run_box_rc "grep -q DOES_NOT_EXIST '$DATA/log.txt'"
assert_rc "grep -q not found" 1 "$RC"

OUT=$(run_box "grep -n ERROR '$DATA/log.txt'")
EXP=$(printf '2:ERROR disk full\n4:ERROR network down')
assert_eq "grep -n" "$EXP" "$OUT"

OUT=$(run_box "grep -v INFO '$DATA/log.txt' | wc -l")
assert_eq "grep -v" "2" "$OUT"

# 9b) tail -n on a file
OUT=$(run_box "tail -n 2 '$DATA/log.txt'")
EXP=$(printf 'ERROR network down\nINFO end')
assert_eq "tail -n file" "$EXP" "$OUT"

# 10) rm: combined flags -rf
OUT=$(run_box "mkdir -p '$RROOT/rmrf/sub'; echo x > '$RROOT/rmrf/sub/f'; rm -rf '$RROOT/rmrf'; test -e '$RROOT/rmrf' && echo BAD || echo ok")
assert_eq "rm -rf" "ok" "$OUT"

# 10b) cp -p preserves mode (validate via stat output)
OUT=$(run_box "rm -f '$RROOT/m' '$RROOT/m2'; echo x > '$RROOT/m'; chmod 640 '$RROOT/m'; cp -p '$RROOT/m' '$RROOT/m2'; stat '$RROOT/m2' | grep 'perm=640'")
assert_nonempty "cp -p preserves mode" "$OUT"

# 10c) ln -s + readlink
OUT=$(run_box "rm -f '$RROOT/link'; ln -s target '$RROOT/link'; readlink '$RROOT/link'")
assert_eq "readlink symlink" "target" "$OUT"

# 10d) find depth controls
OUT=$(run_box "rm -r -f '$RROOT/fd'; mkdir -p '$RROOT/fd/sub'; find '$RROOT/fd' -maxdepth 0")
assert_eq "find -maxdepth 0" "$RROOT/fd" "$OUT"
OUT=$(run_box "find '$RROOT/fd' -mindepth 1 -maxdepth 1 | sort")
EXP=$(printf '%s\n' "$RROOT/fd/sub")
assert_eq "find mindepth/maxdepth" "$EXP" "$OUT"

# 11) sh script mode + if/while/for
OUT=$(run_script "$DATA/scripts/control.sh")
EXP=$(printf 'IF_OK\nLOOP\nAFTER\na\nbb\nc')
assert_eq "sh script + if/while/for" "$EXP" "$OUT"

# 12) sh script argv + positional parameters ($0..$N)
OUT=$(run_script "$DATA/scripts/argv.sh" one two)
EXP=$(printf 'argv0=%s\nargv1=one\nargv2=two' "$DATA/scripts/argv.sh")
assert_eq "sh script argv + positional params" "$EXP" "$OUT"

# 12b) sh script argv: $# and $@/$*
OUT=$(run_script "$DATA/scripts/argv_params.sh" one two)
EXP=$(printf 'argv0=%s\nargv1=one\nargv2=two\nargc=2\nat=one two\nstar=one two' "$DATA/scripts/argv_params.sh")
assert_eq "sh script argv: argc + at/star" "$EXP" "$OUT"

# 13) sh -c argv + positional parameters
CMD='echo argv0=$0; echo argv1=$1; echo argv2=$2'
OUT=$(run_box_argv "$CMD" zero one two)
EXP=$(printf 'argv0=zero\nargv1=one\nargv2=two')
assert_eq "sh -c argv + positional params" "$EXP" "$OUT"

# 13b) sh -c argv: $# and $@/$*
CMD='echo argc=$#; echo at=$@; echo star=$*'
OUT=$(run_box_argv "$CMD" zero one two)
EXP=$(printf 'argc=2\nat=one two\nstar=one two')
assert_eq "sh -c argv: argc + at/star" "$EXP" "$OUT"

# 14) readelf: introspect an ELF binary and parse stable fields
OUT=$(run_box "readelf -h '$BIN/monacc' | grep '^  Class:' | sed -e 's/.*: //' | head -n 1")
assert_eq "readelf header class" "ELF64" "$OUT"

OUT=$(run_box "readelf -l '$BIN/monacc' | grep -q '^Program Headers:' && readelf -l '$BIN/monacc' | grep -q 'LOAD' && echo ok")
assert_eq "readelf -l has LOAD" "ok" "$OUT"

OUT=$(run_box "readelf -S '$BIN/monacc' | grep -F .text | wc -l")
assert_eq "readelf sections includes .text" "1" "$OUT"

# 15) objdump: basic output sanity (no crash + expected headers)
OUT=$(run_box "objdump -h '$BIN/monacc' | grep -q 'file format elf64-x86-64' && objdump -h '$BIN/monacc' | grep -q '^Sections:' && objdump -h '$BIN/monacc' | grep -q '^Idx Name' && objdump -h '$BIN/monacc' | grep -F -q .text && echo ok")
assert_eq "objdump -h basic" "ok" "$OUT"

OUT=$(run_box "objdump -t '$BIN/monacc' | grep -q '^Symbols:' && objdump -t '$BIN/monacc' | grep -q '^Value' && echo ok")
assert_eq "objdump -t basic" "ok" "$OUT"

# 15b) xxd: offsets and -s on pipes/files (non-seekable + seekable)
OUT=$(run_box "echo -n abcd | xxd -s 1 -l 2 | head -n 1 | sed -e 's/:.*//'")
assert_eq "xxd pipe -s offset" "00000001" "$OUT"

OUT=$(run_box "echo -n abcd | xxd -s 1 -l 2 | head -n 1 | grep -F -q '62 63' && echo ok")
assert_eq "xxd pipe -s content" "ok" "$OUT"

OUT=$(run_box "rm -f '$RROOT/xxdfile'; echo -n abcd > '$RROOT/xxdfile'; xxd -s 2 -l 2 '$RROOT/xxdfile' | head -n 1 | grep -F -q '63 64' && echo ok")
assert_eq "xxd file -s content" "ok" "$OUT"

# 16) cpio + xxd: create/list/extract round-trip (pipes + cwd interactions)
OUT=$(run_box "rm -r -f '$RROOT/cpio'; mkdir -p '$RROOT/cpio/src/sub'; echo -n HELLO > '$RROOT/cpio/src/a'; echo -n WORLD > '$RROOT/cpio/src/sub/b'; cd '$RROOT/cpio/src'; echo a > '$RROOT/cpio/list'; echo sub/b >> '$RROOT/cpio/list'; cpio -o < '$RROOT/cpio/list' > '$RROOT/cpio/archive.cpio'; xxd -l 6 '$RROOT/cpio/archive.cpio' | grep -q '070701' && echo ok")
assert_eq "cpio create + xxd magic" "ok" "$OUT"

run_box_rc "echo '../x' | cpio -o > '$RROOT/cpio/bad.cpio'"
assert_rc "cpio rejects unsafe .. path" 1 "$RC"

OUT=$(run_box "cpio -t < '$RROOT/cpio/archive.cpio' | sort")
EXP=$(printf 'a\nsub/b')
assert_eq "cpio list" "$EXP" "$OUT"

OUT=$(run_box "rm -r -f '$RROOT/cpio/out1'; mkdir -p '$RROOT/cpio/out1'; cd '$RROOT/cpio/out1'; cpio -i < '$RROOT/cpio/archive.cpio'; cmp '$RROOT/cpio/src/a' '$RROOT/cpio/out1/a' >/dev/null; cmp '$RROOT/cpio/src/sub/b' '$RROOT/cpio/out1/sub/b' >/dev/null; echo ok")
assert_eq "cpio extract + cmp" "ok" "$OUT"

OUT=$(run_box "rm -r -f '$RROOT/cpio/out2'; mkdir -p '$RROOT/cpio/out2'; cd '$RROOT/cpio/out2'; uncpio < '$RROOT/cpio/archive.cpio'; cmp '$RROOT/cpio/src/a' '$RROOT/cpio/out2/a' >/dev/null; cmp '$RROOT/cpio/src/sub/b' '$RROOT/cpio/out2/sub/b' >/dev/null; echo ok")
assert_eq "uncpio wrapper" "ok" "$OUT"

if [ "$COUNT_ONLY" = "1" ]; then
  echo "$CHECKS"
fi

exit 0
