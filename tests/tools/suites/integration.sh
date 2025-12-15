#!/bin/sh
set -eu

BIN=${1:?usage: integration.sh /path/to/sysbox/bin /path/to/tmpdir}
TMP=${2:?usage: integration.sh /path/to/sysbox/bin /path/to/tmpdir}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../lib/testlib.sh"

mark "sysbox integration"

if [ "$VERBOSE" = "1" ]; then
	echo "=== sysbox integration ===" >&2
	echo "BIN=$BIN" >&2
	echo "TMP=$TMP" >&2
fi

# 1) PATH lookup + basic stdout
mark "echo"
OUT=$(run_box "echo hi")
assert_eq "echo via sysbox sh" "hi" "$OUT"

# 2) Pipelines
mark "pipe wc"
OUT=$(run_box "seq 2 | wc -l")
assert_eq "pipeline wc -l" "2" "$OUT"

# 3) Redirects: > and <
mark "redir"
F1="$TMP/integration_f1"
OUT=$(run_box "echo hello > '$F1'; cat < '$F1'")
assert_eq "redirect cat" "hello" "$OUT"

# 4) Append redirect >>
mark "append"
F2="$TMP/integration_f2"
OUT=$(run_box "echo a > '$F2'; echo b >> '$F2'; wc -l < '$F2'")
assert_eq "append + wc" "2" "$OUT"

# 5) Sequencing with ';'
mark "semicolon"
OUT=$(run_box "echo a; echo b")
EXP=$(printf 'a\nb')
assert_eq "semicolon sequencing" "$EXP" "$OUT"

# 6) grep + wc
mark "grep"
OUT=$(run_box "seq 3 | tr 123 aba | grep a | wc -l")
assert_eq "grep|wc" "2" "$OUT"

# 7) sort | uniq
mark "sort uniq"
OUT=$(run_box "seq 3 | tr 123 bab | sort | uniq")
EXP=$(printf 'a\nb')
assert_eq "sort|uniq" "$EXP" "$OUT"

# 8) tr in pipeline
mark "tr"
OUT=$(run_box "echo hi | tr i o")
assert_eq "tr pipeline" "ho" "$OUT"

# 9) xargs
mark "xargs"
OUT=$(run_box "echo one two | xargs echo prefix")
assert_eq "xargs" "prefix one two" "$OUT"

# 10) find + basic filesystem operations (only sysbox tools)
mark "find"
FROOT="$TMP/integration_find"
OUT=$(run_box "rm -r -f '$FROOT'; mkdir -p '$FROOT/sub'; echo x > '$FROOT/a'; echo y > '$FROOT/sub/b'; find '$FROOT' -name b -type f")
assert_eq "find" "$FROOT/sub/b" "$OUT"

OUT=$(run_box "find '$FROOT' -type f -exec echo {} ';' | sort")
EXP=$(printf '%s\n%s' "$FROOT/a" "$FROOT/sub/b")
assert_eq "find -exec" "$EXP" "$OUT"

OUT=$(run_box "find '$FROOT' -name b -type f -print -exec echo FOUND:{} ';' | sort")
EXP=$(printf '%s\nFOUND:%s' "$FROOT/sub/b" "$FROOT/sub/b")
assert_eq "find -print -exec" "$EXP" "$OUT"

# 11) cd builtin + pwd tool
mark "cd"
CDDIR="$TMP/integration_cd"
OUT=$(run_box "mkdir -p '$CDDIR'; cd '$CDDIR'; pwd")
assert_eq "cd/pwd" "$CDDIR" "$OUT"

# 12) Exit codes (ensure failure propagates)
mark "exit codes"
run_box_rc "false"
assert_rc "false exit code" 1 "$RC"

run_box_rc "false; true"
assert_rc "compound exit code" 0 "$RC"

# 13) && and || short-circuit
mark "&&/||"
OUT=$(run_box "false && echo NO; true && echo ok; false || echo yes")
EXP=$(printf 'ok\nyes')
assert_eq "&&/|| short-circuit" "$EXP" "$OUT"

# 14) for-loop and minimal $NAME expansion
mark "for"
OUT=$(run_box 'for x in a bb c; do echo $x; done')
EXP=$(printf 'a\nbb\nc')
assert_eq "for loop" "$EXP" "$OUT"

# 15) pipeline exit code propagation
mark "pipe rc"
run_box_rc "true | false"
assert_rc "pipeline rc" 1 "$RC"

# 16) test(1) in shell conditionals
mark "test"
TF="$TMP/integration_test_file"
OUT=$(run_box "rm -f '$TF'; echo x > '$TF'; test -e '$TF' && echo yes || echo no")
assert_eq "test -e" "yes" "$OUT"

if [ "$COUNT_ONLY" = "1" ]; then
	echo "$CHECKS"
fi

exit 0
