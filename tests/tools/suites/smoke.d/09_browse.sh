#!/bin/sh
set -eu

BIN=${1:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}
TMP=${2:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../../lib/testlib.sh"

DATA_DIR="$SELF_DIR/../../data/html"

# WP0: usage behavior
set +e
"$BIN/browse" >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "browse with no args should be usage error (got $RC)"

set +e
"$BIN/browse" --nope >/dev/null 2>&1
RC=$?
set -e
[ $RC -eq 2 ] || fail "browse invalid flag should be usage error (got $RC)"

# WP1: deterministic HTML rendering fixtures
check_fixture() {
  NAME=$1
  OUT=$("$BIN/browse" --render-html "$DATA_DIR/$NAME.html")
  EXP=$(cat "$DATA_DIR/$NAME.txt")
  [ "$OUT" = "$EXP" ] || fail "browse --render-html $NAME mismatch"
}

check_fixture basic
check_fixture lists
check_fixture pre
check_fixture entities
check_fixture skip

# stdin mode
OUT=$(printf '<p>hi</p>' | "$BIN/browse" --render-html -)
EXP=$(printf 'hi\n\nLinks:\n')
[ "$OUT" = "$EXP" ] || fail "browse stdin render mismatch"

exit 0
