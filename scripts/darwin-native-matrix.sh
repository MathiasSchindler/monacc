#!/bin/sh
set -u

# darwin-native-matrix.sh
#
# Generates a Markdown report for macOS native aarch64-darwin status by attempting
# to compile every tools/*.c via monacc.
#
# Intended invocation:
#   make darwin-native-smoke DARWIN_NATIVE_MATRIX=1

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

TARGET=${DARWIN_NATIVE_MATRIX_TARGET:-aarch64-darwin}
OUT_MD=${DARWIN_NATIVE_MATRIX_OUT:-"$ROOT_DIR/bin-host/darwin-native-matrix.md"}
LOG_DIR=${DARWIN_NATIVE_MATRIX_LOGDIR:-"$ROOT_DIR/bin-host/matrix-logs"}

MONACC="$ROOT_DIR/bin-host/monacc"
TOOLS_DIR="$ROOT_DIR/tools"

if [ ! -x "$MONACC" ]; then
  echo "error: missing $MONACC (run make darwin-monacc)" >&2
  exit 2
fi

mkdir -p "$(dirname -- "$OUT_MD")" "$LOG_DIR"

TMPDIR_BASE=${TMPDIR:-/tmp}
BUILD_DIR=$(mktemp -d "$TMPDIR_BASE/monacc-matrix.XXXXXX")
trap 'rm -rf "$BUILD_DIR"' EXIT INT TERM

now_utc=$(date -u "+%Y-%m-%d %H:%M:%S UTC" 2>/dev/null || true)

# Escape a string so it can be safely placed in a Markdown table cell.
md_escape_cell() {
  # - Replace '|' to avoid breaking the table.
  # - Replace backticks to avoid accidental code spans.
  # - Collapse newlines to spaces (portable across BSD/GNU tools).
  printf '%s' "$1" \
    | tr '\n' ' ' \
    | sed -e 's/|/\\|/g' -e 's/`/\\`/g'
}

# Map an undefined symbol to a likely core/*.c provider.
core_for_symbol() {
  sym="$1"
  case "$sym" in
    mc_sys_* ) printf '%s' "$ROOT_DIR/core/mc_sys.c" ;;
    mc_regex_*|mc_re_* ) printf '%s' "$ROOT_DIR/core/mc_regex.c" ;;
    mc_sha256_* ) printf '%s' "$ROOT_DIR/core/mc_sha256.c" ;;
    mc_hmac_* ) printf '%s' "$ROOT_DIR/core/mc_hmac.c" ;;
    mc_hkdf_* ) printf '%s' "$ROOT_DIR/core/mc_hkdf.c" ;;
    mc_aes_*|mc_aes128_* ) printf '%s' "$ROOT_DIR/core/mc_aes.c" ;;
    mc_gcm_* ) printf '%s' "$ROOT_DIR/core/mc_gcm.c" ;;
    mc_x25519_* ) printf '%s' "$ROOT_DIR/core/mc_x25519.c" ;;
    mc_tls13_*|mc_tls_* )
      # TLS stack is split across multiple compilation units.
      # Return a space-separated list.
      printf '%s' "$ROOT_DIR/core/mc_tls13.c $ROOT_DIR/core/mc_tls_record.c $ROOT_DIR/core/mc_tls13_client.c $ROOT_DIR/core/mc_tls13_handshake.c $ROOT_DIR/core/mc_tls13_transcript.c" ;;
    * ) printf '%s' "" ;;
  esac
}

# Base core modules that most hosted tools need.
BASE_CORE="$ROOT_DIR/core/mc_io.c $ROOT_DIR/core/mc_str.c $ROOT_DIR/core/mc_fmt.c"

# Generate tool list.
# (Avoid relying on non-POSIX find extensions; tools/ has no spaces.)
TOOL_FILES=$(ls "$TOOLS_DIR"/*.c 2>/dev/null || true)
set -- $TOOL_FILES
TOOL_COUNT=$#

{
  echo "# Darwin native tool matrix"
  echo
  echo "- Generated: ${now_utc:-unknown}"
  printf '%s%s%s\n' '- Target: `' "$TARGET" '`'
  printf '%s\n' '- Command: `make darwin-native-smoke DARWIN_NATIVE_MATRIX=1`'
  echo
  echo "| Tool | Status | Notes | Log |"
  echo "|---|---:|---|---|"
} > "$OUT_MD"

ok=0
fail=0
total=0

for tool_path in $TOOL_FILES; do
  total=$((total + 1))
  tool_file=$(basename -- "$tool_path")
  tool_name=${tool_file%.c}
  out_bin="$BUILD_DIR/${tool_name}-mc"
  log_file="$LOG_DIR/${tool_name}.log"

  # Progress to stderr so users can redirect stdout freely.
  printf '%s\n' "matrix: ${total}/${TOOL_COUNT} ${tool_name}" >&2

  status="FAIL"
  note=""

  # Compile once per tool by default. If we detect a missing core module via
  # undefined-symbol inference, do a single retry with the inferred provider(s)
  # to distinguish true backend failures from missing link inputs.
  # shellcheck disable=SC2086
  "$MONACC" --target "$TARGET" -I "$ROOT_DIR/core" \
    "$tool_path" $BASE_CORE \
    -o "$out_bin" > /dev/null 2> "$log_file"
  rc=$?

  extra_core=""
  if [ $rc -ne 0 ] && grep -q "^Undefined symbols" "$log_file"; then
    miss=$(grep -Eo '"_mc_[A-Za-z0-9_]+"' "$log_file" | head -n 1 | tr -d '"' | sed 's/^_//')
    if [ -n "$miss" ]; then
      extra_core=$(core_for_symbol "$miss")
      if [ -n "$extra_core" ]; then
        tmp_log="$BUILD_DIR/${tool_name}.retry.log"
        # shellcheck disable=SC2086
        "$MONACC" --target "$TARGET" -I "$ROOT_DIR/core" \
          "$tool_path" $BASE_CORE $extra_core \
          -o "$out_bin" > /dev/null 2> "$tmp_log"
        rc2=$?
        {
          echo
          echo "---- retry (auto-added: $extra_core) ----"
          cat "$tmp_log"
        } >> "$log_file"
        rc=$rc2
      fi
    fi
  fi

  if [ $rc -eq 0 ]; then
    status="OK"
    if [ -n "$extra_core" ]; then
      note="compiled (auto-added core)"
    else
      note="compiled"
    fi
  else
    if grep -q "^Undefined symbols" "$log_file"; then
      miss=$(grep -Eo '"_mc_[A-Za-z0-9_]+"' "$log_file" | head -n 1 | tr -d '"' | sed 's/^_//')
      if [ -n "$miss" ]; then
        hint=$(core_for_symbol "$miss")
        if [ -n "$hint" ]; then
          note="undefined ${miss} (hint: add ${hint})"
        else
          note="undefined ${miss}"
        fi
      else
        note="link failed"
      fi
    else
      # Compiler/frontend error: pick the first 'error:' line if possible.
      err_line=$(grep -m 1 -E 'error:' "$log_file" || true)
      if [ -n "$err_line" ]; then
        note="$err_line"
      else
        # Fallback: last non-empty line.
        note=$(awk 'NF{last=$0} END{print last}' "$log_file")
        if [ -z "$note" ]; then
          note="failed"
        fi
      fi
    fi
  fi

  if [ "$status" = "OK" ]; then
    ok=$((ok + 1))
  else
    fail=$((fail + 1))
  fi

  note_cell=$(md_escape_cell "$note")
  log_rel="matrix-logs/${tool_name}.log"

  {
    echo "| ${tool_name} | ${status} | ${note_cell} | [${tool_name}.log](${log_rel}) |"
  } >> "$OUT_MD"

done

{
  echo
  echo "## Totals"
  echo
  echo "- Total: ${total}"
  echo "- OK: ${ok}"
  echo "- FAIL: ${fail}"
} >> "$OUT_MD"

# Always succeed; this is a reporting tool, not a gate.
exit 0
