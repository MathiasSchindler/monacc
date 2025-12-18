#!/bin/bash
# Compare monacc codegen against best-in-class compilers
# Usage: ./scripts/compare_codegen.sh [--all | TOOL]

set -e
export LC_NUMERIC=C  # Use period for decimals

BINDIR="${BINDIR:-bin}"
# Prefer matrix-built monacc tool binaries (bin/monacc_/) when available.
# Fall back to the top-level bin/ for non-matrix builds.
if [[ -d "$BINDIR/monacc_" ]]; then
    MONACC_DIR="$BINDIR/monacc_"
else
    MONACC_DIR="$BINDIR"
fi
COMPILER_DIRS="gcc_15_ clang_20_ gcc_14_ gcc_12_ clang_19_"

# Find smallest binary among reference compilers
find_best() {
    local tool="$1"
    local best=""
    local best_size=999999999
    
    for compiler in $COMPILER_DIRS; do
        local path="$BINDIR/${compiler}/${tool}"
        if [[ -f "$path" ]]; then
            local sz=$(stat -c%s "$path" 2>/dev/null || echo 999999999)
            if (( sz < best_size )); then
                best_size=$sz
                best="$path"
            fi
        fi
    done
    echo "$best"
}

# Count instructions in a binary (works with stripped/sectionless ELF)
count_instructions() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        echo "0"
        return
    fi
    
    # Try objdump -d first (works if sections exist)
    local count
    count=$(objdump -d "$path" 2>/dev/null | grep -cE '^\s+[0-9a-f]+:\s+') || count=0
    
    if [[ "$count" -eq 0 ]]; then
        # Fallback: raw binary disassembly for sectionless ELF
        count=$(objdump -D -b binary -m i386:x86-64 "$path" 2>/dev/null | \
                tail -n +20 | grep -cE '^\s+[0-9a-f]+:\s+') || count=0
    fi
    echo "$count"
}

# Count specific instruction patterns
count_pattern() {
    local path="$1"
    local pattern="$2"
    local count
    
    # Check if objdump -d works (has sections)
    if objdump -d "$path" 2>/dev/null | grep -qE '^\s+[0-9a-f]+:'; then
        count=$(objdump -d "$path" 2>/dev/null | grep -cE "$pattern") || count=0
    else
        count=$(objdump -D -b binary -m i386:x86-64 "$path" 2>/dev/null | \
                tail -n +20 | grep -cE "$pattern") || count=0
    fi
    echo "$count"
}

# Analyze a single tool
analyze_tool() {
    local tool="$1"
    local monacc_bin="$MONACC_DIR/$tool"
    local best_bin=$(find_best "$tool")
    
    if [[ ! -f "$monacc_bin" ]]; then
        echo "$tool: SKIP (no monacc binary)"
        return
    fi
    
    if [[ -z "$best_bin" || ! -f "$best_bin" ]]; then
        echo "$tool: SKIP (no reference binary)"
        return
    fi
    
    local monacc_size=$(stat -c%s "$monacc_bin")
    local best_size=$(stat -c%s "$best_bin")
    local best_name=$(basename $(dirname "$best_bin"))
    
    local monacc_insn=$(count_instructions "$monacc_bin")
    local best_insn=$(count_instructions "$best_bin")
    
    # Specific patterns indicating optimization opportunities
    local monacc_pushpop=$(count_pattern "$monacc_bin" '\s(push|pop)\s')
    local best_pushpop=$(count_pattern "$best_bin" '\s(push|pop)\s')
    
    local monacc_setcc=$(count_pattern "$monacc_bin" '\sset[a-z]+\s+%')
    local best_setcc=$(count_pattern "$best_bin" '\sset[a-z]+\s+%')
    
    local monacc_movslq=$(count_pattern "$monacc_bin" '\smovslq\s')
    local best_movslq=$(count_pattern "$best_bin" '\smovslq\s')
    
    # Calculate ratios
    local size_ratio=$(echo "scale=2; $monacc_size / $best_size" | bc)
    local insn_ratio=$(echo "scale=2; $monacc_insn / $best_insn" | bc 2>/dev/null || echo "N/A")
    
    printf "%-12s %6d vs %6d bytes (%.2fx)  insns: %4d vs %4d  push/pop: %3d vs %3d  setcc: %2d vs %2d  movslq: %2d vs %2d  [%s]\n" \
        "$tool" "$monacc_size" "$best_size" "$size_ratio" \
        "$monacc_insn" "$best_insn" \
        "$monacc_pushpop" "$best_pushpop" \
        "$monacc_setcc" "$best_setcc" \
        "$monacc_movslq" "$best_movslq" \
        "$best_name"
}

# Generate detailed diff for a tool
detailed_diff() {
    local tool="$1"
    local monacc_bin="$MONACC_DIR/$tool"
    local best_bin=$(find_best "$tool")
    
    echo "=== Detailed comparison for: $tool ==="
    echo ""
    echo "--- monacc disassembly (first 100 instructions) ---"
    objdump -D -b binary -m i386:x86-64 "$monacc_bin" 2>/dev/null | tail -n +20 | head -100
    echo ""
    echo "--- best-in-class disassembly (first 100 instructions) ---"
    objdump -d "$best_bin" 2>/dev/null | head -120
}

# Main
if [[ "$1" == "--all" ]]; then
    echo "Tool         monacc vs best (ratio)    instructions      push/pop      setcc     movslq    [compiler]"
    echo "-----------------------------------------------------------------------------------------------------------"
    for tool in $(ls "$MONACC_DIR" 2>/dev/null | grep -v '_$' | head -60); do
        [[ -f "$MONACC_DIR/$tool" ]] && analyze_tool "$tool"
    done | sort -t'(' -k2 -rn
elif [[ "$1" == "--detail" && -n "$2" ]]; then
    detailed_diff "$2"
elif [[ -n "$1" ]]; then
    analyze_tool "$1"
else
    echo "Usage: $0 [--all | --detail TOOL | TOOL]"
    echo ""
    echo "  --all          Compare all tools, sorted by size ratio"
    echo "  --detail TOOL  Show disassembly comparison for TOOL"
    echo "  TOOL           Show metrics for a single tool"
fi
