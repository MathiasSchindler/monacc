#!/bin/sh
set -eu

# Guardrail: ensure the overlap analyzer runs and detects known fixtures.

root_dir=${1:-.}
analyzer_src="$root_dir/tests/repo/overlap.c"
analyzer_bin="$root_dir/build/overlap-test"

mkdir -p "$root_dir/build"

# Build the analyzer with the monacc toolchain and core helpers.
"$root_dir/bin/monacc" -I "$root_dir/core" \
  "$analyzer_src" \
  $root_dir/core/mc_str.c $root_dir/core/mc_fmt.c $root_dir/core/mc_snprint.c \
  $root_dir/core/mc_libc_compat.c $root_dir/core/mc_start_env.c $root_dir/core/mc_io.c \
  $root_dir/core/mc_regex.c \
  -o "$analyzer_bin"

report=$(
  "$analyzer_bin" \
    "$root_dir/tests/repo/overlap-fixtures/alpha.c" \
    "$root_dir/tests/repo/overlap-fixtures/beta.c"
)

printf "%s\n" "$report"

echo "$report" | grep -q "Name collisions across files" || {
  echo "expected name collision section in overlap report" >&2
  exit 1
}

echo "$report" | grep -q "Exact body matches" || {
  echo "expected exact body section in overlap report" >&2
  exit 1
}

echo "$report" | grep -q "Similar bodies" || {
  echo "expected similarity section in overlap report" >&2
  exit 1
}

exit 0
