# Terminal PDF reader plan (syscall-only)

Date: 2025-12-18

This document proposes an implementation plan for a **small, syscall-only, statically-linked** terminal reader focused on **extracting and displaying text** from PDFs.

The goal is *not* to implement a general-purpose PDF engine. The goal is to handle a pragmatic subset of PDFs commonly produced by modern toolchains (LaTeX, Office export, printers), especially where the page content is predominantly text.

Future expansion (optional): add a similar "document-to-terminal" pipeline for **ODT** and **Office Open XML** (DOCX/PPTX/XLSX) once the underlying container/deflate work exists.

---

## 1. Goals

- **Syscall-only**: no dependency on libc at runtime, consistent with monacc tools.
- **Small binary**: comparable to other medium tools; avoid pulling in large subsystems.
- **Text-first**: handle PDFs where information is mainly in text objects, not raster images.
- **Good enough terminal output**:
  - preserve paragraph breaks reasonably
  - preserve basic emphasis when it is easy and reliable (optional)
  - tolerate minor layout loss (columns, precise positioning)

---

## 2. Non-goals (explicitly out of scope)

- Full PDF spec compliance, interactive features, annotations, forms, JS, multimedia.
- Rendering vector graphics, images, gradients, transparency.
- Precise page layout reproduction.
- Full font rasterization, kerning, ligatures, bidi shaping.
- Encrypted PDFs (at least initially).
- Incremental update / cross-reference streams / object streams (initially).

---

## 3. Proposed tool surface

### Tool name
- `bin/pdfcat` (prints extracted text to stdout)

### CLI sketch
- `pdfcat FILE.pdf` (all pages)
- `pdfcat -p 1` (single page)
- `pdfcat -p 3-5` (page range)
- `pdfcat -n` (prefix with page headers)
- `pdfcat --raw` (no reflow; emit lines as discovered)
- `pdfcat --ansi` (enable simple ANSI styles; default off)
- `pdfcat --debug` (optional: dump parsing decisions, object counts)

Integration expectation: `pdfcat file.pdf | more`.

---

## 4. Architecture overview

Treat the reader as a pipeline with hard separation of concerns:

1. **Container layer (PDF file)**
   - random access reads (prefer `mmap`) + bounds checking
   - parse xref + trailer → locate objects

2. **Object model**
   - parse only the PDF types needed: null/bool/int/real/name/string/array/dict/stream
   - resolve indirect references lazily with caching

3. **Stream decoding**
   - initially: `FlateDecode` only (zlib/deflate)
   - later: support common wrappers (`/Filter` arrays, `/DecodeParms` subset)

4. **Document model (minimal)**
   - page tree traversal
   - per-page: list of content streams
   - per-page: resource dictionary (fonts)

5. **Content stream interpreter (text subset)**
   - interpret only text operators; ignore graphics
   - produce a stream of positioned glyphs (or Unicode codepoints)

6. **Text reconstruction**
   - cluster glyphs into lines/words
   - heuristic paragraph detection + optional reflow

7. **Terminal renderer**
   - plain text output as default
   - optional ANSI bold/italic/underline based on coarse signals

---

## 5. PDF subset to target first

### File structure
- Support classic xref tables (`xref ... trailer ... startxref`).
- Support linearized PDFs only as a normal PDF (don’t special-case).

### Objects
- Must support:
  - indirect objects: `n n obj ... endobj`
  - dictionaries and arrays
  - strings:
    - literal strings `( ... )` with escapes
    - hex strings `<...>`
  - names `/Name`
  - streams with `stream\n...\nendstream` and `/Length` (direct or indirect)

### Streams / filters
- Phase 1: only `/Filter /FlateDecode`.
- Phase 2: allow `/Filter [ /FlateDecode ... ]` but still only handle Flate.
- Defer: `/LZWDecode`, `/ASCII85Decode`, `/DCTDecode`.

### Text operators (content streams)
Support the minimum set for real documents:

- Text objects: `BT` / `ET`
- Text state:
  - `Tf` (set font + size)
  - `Tc`, `Tw` (char/word spacing) (optional but useful)
  - `Tz` (horizontal scaling) (optional)
  - `TL` (leading)
- Text positioning:
  - `Td`, `TD`, `Tm`
  - `T*` (next line)
- Text show:
  - `Tj` and `'` and `"`
  - `TJ`

Ignore everything else safely.

---

## 6. Unicode and font strategy (pragmatic)

PDF text extraction is mostly about mapping *glyph codes* to Unicode.

### Priority order
1. **Use `/ToUnicode` CMap** when present (best).
2. Otherwise, if the font uses a known encoding:
   - `/Encoding /WinAnsiEncoding` → map via a small lookup table.
   - `/MacRomanEncoding` (optional).
3. Otherwise, fall back to "best effort": emit `?` for unknown bytes.

### Minimal CMap subset
Implement only what’s needed for ToUnicode in typical PDFs:
- `beginbfchar` / `endbfchar`
- `beginbfrange` / `endbfrange`
- hex codes `<00>` `<0041>` etc

Defer: full CMap parsing, CIDSystemInfo, vertical writing, surrogate pairs edge cases.

---

## 7. Text reconstruction heuristics

PDF is positioning-based; terminals are line/paragraph based.

### Basic approach
- For each page:
  - interpret text and emit tuples like:
    - `page, x, y, font_id, font_size, unicode`
  - then sort primarily by `y` descending, secondarily by `x` ascending.

### Line detection
- Cluster into lines when `|y - y_prev| < k * font_size`.
- Insert spaces when `x_gap > threshold`.

### Paragraph detection
- Blank line when vertical gap between lines exceeds a threshold.
- Optional reflow mode:
  - join lines inside a paragraph and wrap to terminal width.

### Multi-column
- Non-goal initially.
- Later heuristic: detect two x-bands per y-range and emit left column then right.

---

## 8. ANSI styling (optional and conservative)

PDF doesn’t have semantic bold/italic/underline; it has fonts and drawing operations.

A minimal and safe rule set:
- **Bold**: if font name contains `Bold` or `Black`.
- **Italic**: if font name contains `Italic` or `Oblique`.
- **Underline**: default off; optionally detect simple underline lines is too complex for a "small subset" and is probably not worth it.

Gate styling behind `--ansi` so default output is stable and copy/paste-friendly.

---

## 9. Implementation plan (phased)

### Phase 0 — Skeleton + test harness
Deliverables:
- `tools/pdfcat.c` that opens a file, validates `%PDF-` header, prints a friendly error for unsupported PDFs.
- Add a few tiny PDF fixtures under a new test folder (see below).

Tests:
- `make test` adds a new tool test: `pdfcat --version` or `pdfcat FILE` basic smoke.


### Phase 1 — Xref + object loader (classic xref only)
Deliverables:
- Parse:
  - `startxref` → xref offset
  - xref table entries → object offsets
  - trailer dict → `/Root`
- Minimal object parser that can decode primitive objects and dictionaries/arrays.

Tests:
- Fixture: a minimal 1-page PDF using classic xref.
- Unit-ish: verify `/Root` exists, page count extracted.


### Phase 2 — Streams + FlateDecode
Deliverables:
- Implement `FlateDecode` (zlib/deflate) in-tree.
  - Keep it small: fixed Huffman + dynamic Huffman; no gzip container.
  - Implement only what’s needed for typical PDF deflate streams.
- Stream reader that respects `/Length` and bounds.

Tests:
- Fixture where page content stream is Flate-compressed.
- Regression: corrupted stream should fail cleanly (no OOB reads).


### Phase 3 — Page tree traversal + resources
Deliverables:
- Resolve `/Pages` tree:
  - `/Kids`, `/Count`, `/MediaBox`
- For each page:
  - resolve `/Contents` (single stream or array)
  - resolve `/Resources` and `/Font`

Tests:
- Fixture with multiple pages.
- Fixture with `/Contents` as an array.


### Phase 4 — Content stream tokenizer + text operators
Deliverables:
- Tokenize content streams into numbers, names, strings, arrays, operators.
- Implement the text-state machine for BT/ET, positioning, and `Tj`/`TJ`.

Tests:
- Fixture that exercises `Tj`, `'`, `"`, `TJ`.
- Golden output: extracted plain text matches expected.


### Phase 5 — ToUnicode CMap + WinAnsi fallback
Deliverables:
- Parse `/ToUnicode` streams with `bfchar`/`bfrange`.
- If missing, support `/Encoding /WinAnsiEncoding`.

Tests:
- Fixture with ToUnicode mapping (common for subset fonts).
- Fixture that relies on WinAnsi.


### Phase 6 — Text reconstruction (lines/paragraphs) + `--raw`
Deliverables:
- Implement clustering into lines and simple paragraph breaks.
- Implement `--raw` mode to output in parsing order (debuggable).

Tests:
- Fixture with wrapped paragraphs.
- Fixture with headings separated by large y-gaps.


### Phase 7 — Robustness + guardrails
Deliverables:
- Strict bounds checking everywhere.
- Object resolution cycle detection.
- Hard limits (configurable): max objects, max stream size, max recursion depth.

Tests:
- Malformed PDFs: truncated xref, invalid offsets, bogus /Length.


### Phase 8 (optional) — Cross-reference streams / object streams / incremental updates
This is where PDF gets large.

Suggestion: only implement if Phase 0–7 proves valuable and you hit many real PDFs that require it.

---

## 10. Where to put code

A monacc-friendly approach is to keep PDF logic as a small internal library used by one tool:

- `core/mc_pdf.c` / `core/mc_pdf.h`
  - parser, object model, xref
- `core/mc_inflate.c` / `core/mc_inflate.h`
  - deflate implementation (also reusable for DOCX/ODT later)
- `tools/pdfcat.c`
  - CLI + rendering

Important: ensure `bin/monacc` does **not** link the PDF reader code unless it actually uses it.

---

## 11. Test fixtures strategy (no external libs)

Prefer storing tiny PDFs checked into the repo.

Options:
- Hand-crafted minimal PDFs (best for deterministic tests).
- A small set of "real" PDFs but aggressively minimized.

Suggested layout:
- `tests/fixtures/pdf/*.pdf`
- `tests/fixtures/pdf/*.txt` expected output

Then add a `tests/tools/test-pdfcat.sh` that runs:
- `bin/pdfcat tests/fixtures/pdf/minimal.pdf` and compares output.

---

## 12. Future expansion: ODT + OfficeOpenXML

ODT and OOXML are ZIP containers with XML.

If Phase 2 adds a deflate implementation, the next steps become plausible:
- Implement a tiny ZIP reader (central directory, local headers, deflate).
- Parse a strict subset of XML:
  - DOCX: `word/document.xml`
  - ODT: `content.xml`
- Extract text nodes and emit paragraphs.

This should be treated as separate tools (`docxcat`, `odtcat`) reusing a shared `mc_zip` + `mc_inflate`.

---

## 13. Practical note: what will fail (and that’s OK)

Even with ToUnicode support, some PDFs will not extract cleanly because:
- they embed text as vector outlines
- they omit ToUnicode and use custom encodings
- they rely on object streams/xref streams

The tool should detect these cases and degrade gracefully (warn + output partial text), not crash.
