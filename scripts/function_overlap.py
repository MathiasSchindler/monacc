#!/usr/bin/env python3
"""
Function overlap analyzer for monacc.

This lightweight helper scans C sources (default: core/ and tools/) to spot
potentially redundant functions. It looks for:
  - Name collisions across files
  - Identical or near-identical normalized function bodies
  - Token-level similarity above a configurable threshold

The output is a human-readable report with brief refactoring suggestions.
No external dependencies are required beyond the Python standard library.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple


FUNC_DEF_RE = re.compile(
    r"^[ \t]*"  # leading whitespace
    r"(?:static\s+|inline\s+|__attribute__\s*\(\(.*?\)\)\s+)*"  # qualifiers
    r"[A-Za-z_][\w\s\*\(\)]*"  # return type-ish blob
    r"\s+"  # whitespace before name (may span lines)
    r"(?P<name>[A-Za-z_]\w*)"  # function name
    r"\s*\((?P<params>[^;]*?)\)\s*"  # parameters (no semicolon)
    r"\{",  # opening brace
    re.MULTILINE | re.DOTALL,
)

CONTROL_KEYWORDS = {"if", "for", "while", "switch"}
SIMILAR_MAX_SIZE_RATIO = 1.6
SIMILAR_MIN_SIZE_RATIO = 0.5


@dataclass
class FunctionDef:
    name: str
    file: Path
    line: int
    signature: str
    body: str
    normalized: str
    tokens: List[str]


def strip_comments(source: str) -> str:
    """Remove // and /* */ comments to simplify parsing."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    source = re.sub(r"//.*?$", "", source, flags=re.MULTILINE)
    return source


def extract_block(source: str, start_idx: int) -> Tuple[str, int]:
    """Return the block starting at start_idx (pointing to '{') and the end idx."""
    depth = 0
    i = start_idx
    in_quote: str | None = None
    escape = False
    while i < len(source):
        ch = source[i]
        if escape:
            escape = False
        elif ch == "\\":
            escape = True
        elif in_quote:
            if ch == in_quote:
                in_quote = None
        else:
            if ch in ("'", '"'):
                in_quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return source[start_idx : i + 1], i + 1
        i += 1
    return source[start_idx:], len(source)


def normalize_body(body: str) -> Tuple[str, List[str]]:
    """Normalize a function body and return (string form, token list)."""
    body = re.sub(r'"(?:\\.|[^"\\])*"', '"STR"', body)
    body = re.sub(r"'(?:\\.|[^'\\])*'", "'CHR'", body)
    body = re.sub(r"\b0[xX][0-9A-Fa-f]+\b", "0x0", body)
    body = re.sub(r"\b\d+(\.\d+)?\b", "0", body)
    body = re.sub(r"\s+", " ", body).strip()
    tokens = re.findall(
        r"[A-Za-z_]\w+|==|!=|<=|>=|->|&&|\|\||[{}()\[\];,+\-*/%&|^<>!]", body
    )
    return " ".join(tokens), tokens


def iter_functions(path: Path) -> Iterable[FunctionDef]:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    cleaned = strip_comments(raw)
    idx = 0
    while True:
        match = FUNC_DEF_RE.search(cleaned, idx)
        if not match:
            break
        name = match.group("name")
        if name in CONTROL_KEYWORDS:
            idx = match.end()
            continue
        brace_start = cleaned.find("{", match.end() - 1)
        if brace_start == -1:
            break
        body, end_idx = extract_block(cleaned, brace_start)
        signature = cleaned[match.start() : brace_start].strip()
        line_no = cleaned.count("\n", 0, match.start()) + 1
        normalized, tokens = normalize_body(body)
        yield FunctionDef(
            name=name,
            file=path,
            line=line_no,
            signature=signature,
            body=body,
            normalized=normalized,
            tokens=tokens,
        )
        idx = end_idx


def collect_functions(paths: Sequence[Path]) -> List[FunctionDef]:
    functions: List[FunctionDef] = []
    for base in paths:
        if base.is_file() and base.suffix == ".c":
            functions.extend(iter_functions(base))
            continue
        for c_file in base.rglob("*.c"):
            functions.extend(iter_functions(c_file))
    return functions


def group_by_name(functions: Sequence[FunctionDef]) -> List[List[FunctionDef]]:
    buckets: dict[str, List[FunctionDef]] = defaultdict(list)
    for fn in functions:
        buckets[fn.name].append(fn)
    return [group for group in buckets.values() if len({f.file for f in group}) > 1]


def group_by_exact_body(functions: Sequence[FunctionDef]) -> List[List[FunctionDef]]:
    buckets: dict[str, List[FunctionDef]] = defaultdict(list)
    for fn in functions:
        digest = hashlib.sha256(fn.normalized.encode("utf-8")).hexdigest()
        buckets[digest].append(fn)
    return [group for group in buckets.values() if len({f.file for f in group}) > 1]


def find_similar(
    functions: Sequence[FunctionDef], threshold: float, limit: int
) -> List[Tuple[float, FunctionDef, FunctionDef]]:
    pairs: List[Tuple[float, FunctionDef, FunctionDef]] = []
    funcs = sorted(functions, key=lambda f: len(f.tokens))
    for i, left in enumerate(funcs):
        left_len = len(left.tokens)
        if left_len == 0:
            continue
        for right in funcs[i + 1 :]:
            if len(right.tokens) > left_len * SIMILAR_MAX_SIZE_RATIO:
                break  # longer entries will only diverge more
            if left.file == right.file:
                continue
            if left.normalized == right.normalized:
                continue  # exact match handled separately
            longer = max(left_len, len(right.tokens))
            length_ratio = min(left_len, len(right.tokens)) / longer
            if length_ratio < SIMILAR_MIN_SIZE_RATIO:
                continue  # skip wildly different sizes
            score = difflib.SequenceMatcher(None, left.tokens, right.tokens).ratio()
            if score >= threshold:
                pairs.append((score, left, right))
    pairs.sort(key=lambda item: item[0], reverse=True)
    return pairs[:limit]


def relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def print_section(title: str):
    print(title)
    print("-" * len(title))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Find overlapping/redundant functions in monacc sources."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root (defaults to scripts/..)",
    )
    parser.add_argument(
        "--paths",
        nargs="+",
        type=Path,
        default=[Path("core"), Path("tools")],
        help="Directories/files to scan (relative to --root if not absolute).",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.88,
        help="Token similarity threshold for near-duplicates.",
    )
    parser.add_argument(
        "--max-report",
        type=int,
        default=20,
        help="Maximum similar-pair entries to print.",
    )
    parser.add_argument(
        "--fail-on-overlap",
        choices=["name", "exact", "similar", "any"],
        action="append",
        default=[],
        help="Exit non-zero if overlaps of the selected type are found.",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    search_paths = [
        path if path.is_absolute() else root / path for path in args.paths
    ]

    functions = collect_functions(search_paths)
    if not functions:
        print("No functions found in the provided paths.", file=sys.stderr)
        return 1

    by_name = group_by_name(functions)
    by_exact = group_by_exact_body(functions)
    similar = find_similar(functions, args.threshold, args.max_report)

    print(f"monacc function overlap report (threshold={args.threshold:.2f})")
    print(
        "Criteria: name collisions, identical normalized bodies, "
        "token similarity >= threshold."
    )
    print(f"Scanned {len(functions)} functions across {len(set(f.file for f in functions))} files.")
    print("")

    if by_name:
        print_section("Name collisions across files")
        for group in sorted(by_name, key=lambda g: g[0].name):
            files = ", ".join(sorted({relpath(f.file, root) for f in group}))
            print(f"  {group[0].name}: {files}")
        print("  suggestion: consolidate shared helpers or rename for clarity.")
        print("")

    if by_exact:
        print_section("Exact body matches")
        for group in by_exact:
            digest = hashlib.sha256(group[0].normalized.encode("utf-8")).hexdigest()[:8]
            print(f"  hash {digest} shared by {len(group)} functions:")
            for fn in group:
                print(f"    - {fn.name} ({relpath(fn.file, root)}:{fn.line})")
            print("    suggestion: move shared logic into core/ or a common module.")
        print("")

    if similar:
        print_section("Similar bodies (token ratio)")
        for score, left, right in similar:
            print(
                f"  {score:.2f}: {left.name} ({relpath(left.file, root)}:{left.line})"
                f" <-> {right.name} ({relpath(right.file, root)}:{right.line})"
            )
        print(
            "  suggestion: review similar pairs for potential refactors or "
            "shared utilities."
        )
        print("")

    if not (by_name or by_exact or similar):
        print("No overlaps detected with current heuristics.")

    fail_set = set(args.fail_on_overlap)
    should_fail = False
    if "any" in fail_set and (by_name or by_exact or similar):
        should_fail = True
    if "name" in fail_set and by_name:
        should_fail = True
    if "exact" in fail_set and by_exact:
        should_fail = True
    if "similar" in fail_set and similar:
        should_fail = True

    return 1 if should_fail else 0


if __name__ == "__main__":
    sys.exit(main())
