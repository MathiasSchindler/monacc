#!/bin/sh
set -eu

BIN=${1:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}
TMP=${2:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../../lib/testlib.sh"

DATA_DIR="$SELF_DIR/../../data/html"
HTTP_DIR="$SELF_DIR/../../data/http"

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

# WP2: deterministic parsing helpers (no live network)
OUT=$("$BIN/browse" --parse-url example.com)
EXP=$(cat "$HTTP_DIR/url_default.out")
[ "$OUT" = "$EXP" ] || fail "browse --parse-url default mismatch"

OUT=$("$BIN/browse" --parse-url http://example.com:8080/a/b)
EXP=$(cat "$HTTP_DIR/url_http_port_path.out")
[ "$OUT" = "$EXP" ] || fail "browse --parse-url explicit port/path mismatch"

OUT=$("$BIN/browse" --parse-url http://[::1]/x)
EXP=$(cat "$HTTP_DIR/url_ipv6.out")
[ "$OUT" = "$EXP" ] || fail "browse --parse-url ipv6 mismatch"

OUT=$(cat "$HTTP_DIR/headers1.in" | "$BIN/browse" --parse-http-headers)
EXP=$(cat "$HTTP_DIR/headers1.out")
[ "$OUT" = "$EXP" ] || fail "browse --parse-http-headers headers1 mismatch"

OUT=$(cat "$HTTP_DIR/headers2.in" | "$BIN/browse" --parse-http-headers)
EXP=$(cat "$HTTP_DIR/headers2.out")
[ "$OUT" = "$EXP" ] || fail "browse --parse-http-headers headers2 mismatch"

OUT=$(cat "$HTTP_DIR/chunked1.in" | "$BIN/browse" --decode-chunked)
EXP=$(cat "$HTTP_DIR/chunked1.out")
[ "$OUT" = "$EXP" ] || fail "browse --decode-chunked chunked1 mismatch"

OUT=$(cat "$HTTP_DIR/chunked2.in" | "$BIN/browse" --decode-chunked)
EXP=$(cat "$HTTP_DIR/chunked2.out")
[ "$OUT" = "$EXP" ] || fail "browse --decode-chunked chunked2 mismatch"

exit 0
