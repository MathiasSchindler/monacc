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

# WP3: relative URL resolution (base-aware offline render)
OUT=$("$BIN/browse" --render-html-base http://example.com/a/b/index.html "$DATA_DIR/relative.html")
EXP=$(cat "$DATA_DIR/relative.txt")
[ "$OUT" = "$EXP" ] || fail "browse --render-html-base relative mismatch"

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

OUT=$("$BIN/browse" --parse-url https://example.com/)
EXP=$(cat "$HTTP_DIR/url_https_default.out")
[ "$OUT" = "$EXP" ] || fail "browse --parse-url https default mismatch"

# WP3: resolve-url helper
OUT=$("$BIN/browse" --resolve-url http://example.com/a/b/index.html /abs)
EXP=$(cat "$HTTP_DIR/resolve_abs.out")
[ "$OUT" = "$EXP" ] || fail "browse --resolve-url abs mismatch"

OUT=$("$BIN/browse" --resolve-url http://example.com/a/b/index.html rel.html)
EXP=$(cat "$HTTP_DIR/resolve_rel.out")
[ "$OUT" = "$EXP" ] || fail "browse --resolve-url rel mismatch"

OUT=$("$BIN/browse" --resolve-url http://example.com/a/b/index.html ../up.html)
EXP=$(cat "$HTTP_DIR/resolve_up.out")
[ "$OUT" = "$EXP" ] || fail "browse --resolve-url up mismatch"

OUT=$("$BIN/browse" --resolve-url http://example.com/a/b/index.html http://other/x)
EXP=$(cat "$HTTP_DIR/resolve_scheme.out")
[ "$OUT" = "$EXP" ] || fail "browse --resolve-url scheme mismatch"

OUT=$("$BIN/browse" --resolve-url http://example.com/a/b/index.html mailto:test@example.com)
EXP=$(cat "$HTTP_DIR/resolve_keepraw.out")
[ "$OUT" = "$EXP" ] || fail "browse --resolve-url keepraw mismatch"

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
