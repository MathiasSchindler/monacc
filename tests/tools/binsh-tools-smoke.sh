# Smoke-test a handful of sysbox tools under ./bin/sh.
# Constraint: must be runnable under our minimal shell:
# - no functions
# - no ${...} expansions
# - no $(...) command substitution
# - no job control (but supports basic background '&' + builtin wait)

BIN=./bin
TMP=/tmp/monacc-binsh-tools-$$

"$BIN/rm" -rf "$TMP"
"$BIN/mkdir" -p "$TMP"

# cat -n
"$BIN/printf" 'a\n\n b\n' > "$TMP/in_cat"
"$BIN/printf" '1\ta\n2\t\n3\t b\n' > "$TMP/exp_cat_n"
"$BIN/cat" -n "$TMP/in_cat" > "$TMP/out_cat_n"
"$BIN/cmp" "$TMP/exp_cat_n" "$TMP/out_cat_n" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then "$BIN/true" >/dev/null; else
	"$BIN/echo" "binsh-tools-smoke: FAIL: cat -n"
	exit 1
fi

# pipeline: seq | wc -l
"$BIN/printf" '3\n' > "$TMP/exp_wc"
"$BIN/seq" 3 | "$BIN/wc" -l > "$TMP/out_wc"
"$BIN/cmp" "$TMP/exp_wc" "$TMP/out_wc" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then "$BIN/true" >/dev/null; else
	"$BIN/echo" "binsh-tools-smoke: FAIL: seq|wc -l"
	exit 1
fi

# grep + sed
"$BIN/printf" 'a\nb\n' > "$TMP/in_grep"
"$BIN/printf" 'x\n' > "$TMP/exp_grep"
"$BIN/grep" b "$TMP/in_grep" | "$BIN/sed" 's/b/x/' > "$TMP/out_grep"
"$BIN/cmp" "$TMP/exp_grep" "$TMP/out_grep" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then "$BIN/true" >/dev/null; else
	"$BIN/echo" "binsh-tools-smoke: FAIL: grep|sed"
	exit 1
fi

# sort | uniq
"$BIN/printf" 'b\na\na\n' > "$TMP/in_sort"
"$BIN/printf" 'a\nb\n' > "$TMP/exp_sort"
"$BIN/sort" "$TMP/in_sort" | "$BIN/uniq" > "$TMP/out_sort"
"$BIN/cmp" "$TMP/exp_sort" "$TMP/out_sort" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then "$BIN/true" >/dev/null; else
	"$BIN/echo" "binsh-tools-smoke: FAIL: sort|uniq"
	exit 1
fi

# Redirection: ensure our minimal shell supports fd duplication.
"$BIN/printf" '' > "$TMP/empty"
"$BIN/sh" -c "$BIN/cat /no_such_file 2>&1" > "$TMP/out_dup"
"$BIN/cmp" "$TMP/empty" "$TMP/out_dup" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then
	"$BIN/echo" "binsh-tools-smoke: FAIL: 2>&1 produced empty output"
	exit 1
fi

"$BIN/sh" -c "$BIN/echo hi >&2" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then "$BIN/true" >/dev/null; else
	"$BIN/echo" "binsh-tools-smoke: FAIL: >&2 parse"
	exit 1
fi

# Background + wait + $!
# (Also ensure comments containing '&' don't break parsing.)
"$BIN/printf" '' > "$TMP/out_bg_pid"
"$BIN/sh" -c "# comment with & should be ignored
$BIN/sleep 1 & PID=$!; $BIN/echo $PID > $TMP/out_bg_pid; wait $PID" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then "$BIN/true" >/dev/null; else
	"$BIN/echo" "binsh-tools-smoke: FAIL: background '&' or wait"
	exit 1
fi
"$BIN/cmp" "$TMP/empty" "$TMP/out_bg_pid" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then
	"$BIN/echo" "binsh-tools-smoke: FAIL: $! produced empty pid"
	exit 1
fi

# Shell features: set -e/+e, ':', ${...}, $((...)), functions, '.', $(...)

# set -e should stop execution on failure
"$BIN/printf" '' > "$TMP/out_sete"
"$BIN/sh" -c 'set -e; ./bin/false; ./bin/echo NO' > "$TMP/out_sete" 2>/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then
	"$BIN/echo" "binsh-tools-smoke: FAIL: set -e did not abort"
	exit 1
fi
"$BIN/cmp" "$TMP/empty" "$TMP/out_sete" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then "$BIN/true" >/dev/null; else
	"$BIN/echo" "binsh-tools-smoke: FAIL: set -e printed output"
	exit 1
fi

# ':' and ${VAR:=default} defaulting
"$BIN/printf" '42\n' > "$TMP/exp_param"
"$BIN/sh" -c 'X=; : "${X:=42}"; ./bin/echo $X' > "$TMP/out_param"
"$BIN/cmp" "$TMP/exp_param" "$TMP/out_param" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then "$BIN/true" >/dev/null; else
	"$BIN/echo" "binsh-tools-smoke: FAIL: \${VAR:=...}"
	exit 1
fi

# ${1:?msg} should fail when missing
"$BIN/sh" -c ': "${1:?missing}"' x >/dev/null 2>/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then
	"$BIN/echo" "binsh-tools-smoke: FAIL: \${1:?} did not fail"
	exit 1
fi

# $((...)) arithmetic expansion
"$BIN/printf" '3\n' > "$TMP/exp_arith"
"$BIN/sh" -c 'N=1; N=$((N + 2)); ./bin/echo $N' > "$TMP/out_arith"
"$BIN/cmp" "$TMP/exp_arith" "$TMP/out_arith" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then "$BIN/true" >/dev/null; else
	"$BIN/echo" "binsh-tools-smoke: FAIL: \$((...))"
	exit 1
fi

# Functions
"$BIN/printf" 'ok\n' > "$TMP/exp_func"
"$BIN/sh" -c 'f() { ./bin/echo ok; } ; f' > "$TMP/out_func"
"$BIN/cmp" "$TMP/exp_func" "$TMP/out_func" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then "$BIN/true" >/dev/null; else
	"$BIN/echo" "binsh-tools-smoke: FAIL: functions"
	exit 1
fi

# '.' source
"$BIN/printf" 'g() { ./bin/echo hi; }\n' > "$TMP/src"
"$BIN/printf" 'hi\n' > "$TMP/exp_src"
"$BIN/sh" -c ". $TMP/src; g" > "$TMP/out_src"
"$BIN/cmp" "$TMP/exp_src" "$TMP/out_src" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then "$BIN/true" >/dev/null; else
	"$BIN/echo" "binsh-tools-smoke: FAIL: source (.)"
	exit 1
fi

# $(...) command substitution
"$BIN/printf" 'hi\n' > "$TMP/exp_cmdsub"
"$BIN/sh" -c 'X=$(./bin/echo hi); ./bin/echo $X' > "$TMP/out_cmdsub"
"$BIN/cmp" "$TMP/exp_cmdsub" "$TMP/out_cmdsub" >/dev/null
RC=$?
if "$BIN/test" "$RC" = 0; then "$BIN/true" >/dev/null; else
	"$BIN/echo" "binsh-tools-smoke: FAIL: \$(...)"
	exit 1
fi

"$BIN/rm" -rf "$TMP"
exit 0
