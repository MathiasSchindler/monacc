#!/bin/sh
set -eu

BIN=${1:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}
TMP=${2:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../../lib/testlib.sh"

mark "wtf"

OUT=$("$BIN/wtf" --smoke)
EXP=$(printf '%s\n%s\n%s\n%s' \
  "url central%20nervous%20system" \
  "extract_sha256 4a10768e736ad609d8c340167c7629484e655746ae0eb9d3ac2c31dd0583b202" \
  "short_sha256 78de19c68a4e0f0eaa3d669c23cff257c38d082e69bdb13517eb3e28ca6d9b1f" \
  "opensearch_title Caffeine")
assert_eq "wtf smoke" "$EXP" "$OUT"

exit 0
