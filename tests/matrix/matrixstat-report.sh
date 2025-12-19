#!/bin/sh
set -eu

# Emit a TSV matrixstat report for bin/<tc_dir>/*
# Usage:
#   sh tests/matrix/matrixstat-report.sh [tc...]
# If no args, uses the same default set as build-matrix.sh.
# Override defaults via MATRIX_TCS (space-separated), e.g.:
#   MATRIX_TCS="monacc gcc-15 clang-21" sh tests/matrix/matrixstat-report.sh
#
# Output:
#   build/matrix/matrixstat.tsv
#
# Notes:
# - This runs ./bin/matrixstat once per compiler dir (so it only reports the
#   toolchains selected for this matrix run, even if older bin/*_*/ dirs exist).

. "$(dirname "$0")/common.sh"

ROOT="$(repo_root)"
cd "$ROOT"

if [ "$#" -gt 0 ]; then
	TCS="$*"
else
	TCS="$(default_toolchains)"
fi

if [ ! -x ./bin/matrixstat ]; then
	die "matrixstat-report: missing ./bin/matrixstat (run: make)"
fi

OUT_DIR="build/matrix"
OUT_TSV="$OUT_DIR/matrixstat.tsv"
mkdir -p "$OUT_DIR"

# Default to per-tool output (includes __TOTAL__ rows too).
ARGS="--per-tool"
if [ -n "${MATRIXSTAT_ARGS:-}" ]; then
	# Advanced escape hatch.
	ARGS="$MATRIXSTAT_ARGS"
fi

first=1
for tc in $TCS; do
	TC_DIR="$(tc_dirname "$tc")"
	BIN="bin/$TC_DIR"
	if [ ! -d "$BIN" ]; then
		continue
	fi
	if [ "$first" -eq 1 ]; then
		./bin/matrixstat $ARGS --only "$TC_DIR" >"$OUT_TSV"
		first=0
	else
		./bin/matrixstat $ARGS --only "$TC_DIR" | sed '1d' >>"$OUT_TSV"
	fi

done

# If nothing was written (no toolchains found), emit only a header.
if [ "$first" -eq 1 ]; then
	./bin/matrixstat $ARGS --only monacc_ 2>/dev/null | head -n 1 >"$OUT_TSV" || true
fi

# Validate TSV format and basic invariants so regressions are visible in MULTI=1 make test.
# (Keep this POSIX-sh + awk, no dependencies.)
awk -F '\t' '
	NR==1 {
		ncol = NF;
		for (i=1; i<=NF; i++) idx[$i]=i;
		need["compiler"]=1; need["tool"]=1; need["n_ok"]=1; need["n_err"]=1;
		need["file_bytes"]=1; need["text_bytes"]=1;
		need["scan_mode"]=1; need["n_exec_regions"]=1; need["n_exec_off0"]=1;
		need["exec_coverage_ppm"]=1; need["n_scan_shdr"]=1; need["n_scan_phdr"]=1;
		for (k in need) {
			if (!(k in idx)) { print "matrixstat-report: missing column: " k > "/dev/stderr"; exit 1 }
		}
		next
	}
	{
		if (NF != ncol) { print "matrixstat-report: bad column count on line " NR " (got " NF ", want " ncol ")" > "/dev/stderr"; exit 1 }
		n_ok = $(idx["n_ok"])+0;
		if (n_ok > 0) {
			sm = $(idx["scan_mode"]);
			if (sm != "shdr" && sm != "phdr" && sm != "mixed") {
				print "matrixstat-report: bad scan_mode on line " NR ": " sm > "/dev/stderr"; exit 1
			}
			n_exec = $(idx["n_exec_regions"])+0;
			if (n_exec <= 0) { print "matrixstat-report: n_exec_regions <= 0 on line " NR > "/dev/stderr"; exit 1 }
			cov = $(idx["exec_coverage_ppm"])+0;
			if (cov <= 0) { print "matrixstat-report: exec_coverage_ppm <= 0 on line " NR > "/dev/stderr"; exit 1 }
			a = $(idx["n_scan_shdr"])+0;
			b = $(idx["n_scan_phdr"])+0;
			if (a + b != n_ok) { print "matrixstat-report: n_scan_shdr+n_scan_phdr != n_ok on line " NR > "/dev/stderr"; exit 1 }
		}
		# Repository-specific sanity check: monacc outputs are typically sectionless.
		if ($(idx["compiler"]) == "monacc_" && $(idx["tool"]) == "__TOTAL__") {
			if ($(idx["n_scan_phdr"])+0 <= 0) { print "matrixstat-report: expected monacc_ __TOTAL__ to use phdr scanning" > "/dev/stderr"; exit 1 }
		}
	}
' "$OUT_TSV" >/dev/null
