#!/bin/sh
set -eu

# Guardrail: ensure the overlap analyzer runs and detects known fixtures.

root_dir=${1:-.}
analyzer="$root_dir/bin/overlap"

if [ ! -x "$analyzer" ]; then
  echo "missing analyzer: $analyzer" >&2
  exit 1
fi

report=$(
  "$analyzer" \
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
