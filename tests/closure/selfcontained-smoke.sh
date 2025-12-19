# Self-contained closure smoke, runnable under ./bin/sh.
# Uses only features supported by our minimal shell.

OUT=/tmp/monacc-closure-hello

# Compile with fully-internal pipeline.
./bin/monacc --emit-obj --link-internal examples/hello.c -o "$OUT"

# Verify the expected exit code (examples return 42).
"$OUT" >/dev/null
RC=$?

if ./bin/test "$RC" = 42; then
	./bin/echo "closure-smoke: OK" >/dev/null
	./bin/rm -f "$OUT"
	exit 0
fi

./bin/echo "closure-smoke: FAIL"
./bin/rm -f "$OUT"
exit 1
