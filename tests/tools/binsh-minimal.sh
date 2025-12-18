# Minimal script intended to run under ./bin/sh.
# Constraint: avoid variable expansion, command substitution, and functions.

OUT=/tmp/monacc-binsh-smoke-out

./bin/echo ok >/dev/null

# Basic -c execution.
./bin/sh -c './bin/echo ok >/dev/null'

# Pipeline + external tools (bin/sh supports pipes and ||/&&).
./bin/sh -c './bin/printf "a\nb\n" | ./bin/grep b | ./bin/sed s/b/x/ | ./bin/wc -l >/dev/null'

# Redirections.
./bin/sh -c "./bin/echo hi > $OUT"
./bin/sh -c "./bin/cat < $OUT | ./bin/wc -c >/dev/null"

# Clean up.
./bin/rm -f "$OUT"

exit 0
