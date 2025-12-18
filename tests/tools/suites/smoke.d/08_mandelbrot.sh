#!/bin/sh
set -eu

BIN=${1:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}
TMP=${2:?usage: smoke-part.sh /path/to/sysbox/bin /path/to/tmpdir}

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SELF_DIR/../../lib/testlib.sh"
mark "mandelbrot"

OUTF="$TMP/mandelbrot.bmp"

# 16x16, 24-bit BMP
W=16
H=16
IT=20

"$BIN/mandelbrot" -w $W -h $H -i $IT >"$OUTF" || fail "mandelbrot should exit 0"

MAGIC=$("$BIN/head" -c 2 "$OUTF")
[ "$MAGIC" = "BM" ] || fail "mandelbrot should emit BMP magic 'BM' (got '$MAGIC')"

# File size = 54 header + H * rowbytes, rowbytes is padded to 4 bytes.
ROWBYTES=$(( (W * 3 + 3) & ~3 ))
EXP_SIZE=$(( 54 + H * ROWBYTES ))
ACT_SIZE=$(stat -c %s "$OUTF")
[ "$ACT_SIZE" -eq "$EXP_SIZE" ] || fail "mandelbrot bmp size unexpected: got $ACT_SIZE, expected $EXP_SIZE"

exit 0
