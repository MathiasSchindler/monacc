# Text-mode web browser (monacc)

Date: 2025-12-20

This document specifies a minimalist, syscall-only, text-mode web browser for monacc.

The goal is *not* to re-create a full `lynx`/`links`, but to get a useful “debugging browser” for the monacc VM:

- Fetch `http(s)://…` pages
- Render a readable text approximation
- Extract and list links
- Follow links interactively

Constraints: same as the rest of monacc tools:

- syscall-only (no libc)
- stable-ish text output
- small, explicit feature subset
- consistent exit codes: `0` success, `1` operational error, `2` usage error

---

## 1) Scope and CLI

### 1.1 Tool name

Proposed tool: `browse`.

### 1.2 Modes

Two modes keep it testable and usable:

1) **Dump mode** (default, non-interactive): fetch + render to stdout.
2) **Interactive mode** (`-i`): fetch + render, then accept commands from `/dev/tty`.

### 1.3 CLI (v0)

- `browse URL`
  - Fetch URL
  - Render to stdout
  - Append a link table (numbered)

- `browse -dump-links URL`
  - Fetch URL
  - Print only the numbered link table

- `browse -i URL`
  - Interactive session:
    - shows rendered page in a pager-style flow
    - lets the user follow numbered links

Notes:
- URL grammar is intentionally small and strict.
- Output should be deterministic for local fixtures (tests).

### 1.4 Output format (stable-ish)

Dump mode output:

- Rendered text body (wrapped minimally or not at all; see renderer rules)
- Blank line
- `Links:` section
- Each link on its own line: `N URL`

Example:

```
Hello world.

Links:
1 https://example.com/
2 /about
```

(For relative URLs, `browse` prints the resolved absolute URL in the Links section once resolution is implemented.)

---

## 2) Networking plan (fetch layer)

The browser should be built around a small “fetch layer” that returns:

- final URL (after redirects)
- response metadata: status code, content-type
- body bytes (streamed to a consumer)

### 2.1 URL parsing

Support only:

- `http://HOST[:PORT]/PATH`
- `https://HOST[:PORT]/PATH`
- HOST may be:
  - bracketed IPv6 literal: `[2001:db8::1]`
  - hostname (AAAA-only resolution)

Defaults:

- If scheme omitted: treat as `http://`.
- Default ports:
  - http: 80
  - https: 443
- If path omitted: `/`.

Hard limits (initial):

- host length: ≤ 255
- path length: ≤ 2048
- redirects: depth ≤ 5

### 2.2 DNS resolution (AAAA)

Use the existing approach from the net tools:

- Parse IPv6 literal directly when possible.
- Otherwise resolve AAAA via `/etc/resolv.conf` (fallback to public resolver if needed).

This matches current IPv6-only networking tooling.

### 2.3 HTTP/1.1 over TCP (http://)

Implementation approach:

- Use `wget6` patterns:
  - connect timeout via non-blocking socket + `poll`
  - send `GET` with `Host:` and `Connection: close`
  - parse status line and headers
  - decode body for:
    - `Content-Length`
    - `Transfer-Encoding: chunked`

Behavior:

- Non-2xx is an operational failure (`exit 1`) unless `-i` is used and we decide to render an error banner.

### 2.4 Redirects

Needed for real browsing.

Minimal redirect handling:

- Follow `301/302/303/307/308` when `Location:` is present.
- Resolve `Location`:
  - absolute URL: `http(s)://…`
  - absolute path: `/…` (same scheme/host/port)

Cap:

- max depth 5, then fail.

### 2.5 HTTPS strategy

We already have a TLS 1.3 implementation (see docs/tls.md). For browsing, we want an internal API to “GET over TLS”.

Two staged options:

**A) In-process TLS fetch (preferred)**
- Factor the essentials of `tls13 hs` into a helper used by `browse`.
- Must support:
  - DNS+connect timeout
  - SNI
  - sending HTTP request as application data
  - reading/decrypting application data until close
- Must be *quiet* (no debug spew to stderr in normal mode).

**B) Shell out to `tls13 hs` (bootstrap-only)**
- `browse` could exec `tls13 hs -n … -p … HOST 443` and read stdout.
- Not ideal:
  - hard to implement redirects/content-type parsing cleanly
  - tight coupling to tool output

Security note (must be documented in tool `--help` and in this doc):

- **No certificate validation** (no X.509). HTTPS is encrypted but not authenticated.

---

## 3) HTML → text rendering plan

The renderer should work without building a DOM. It should be a streaming-ish tokenizer + small state machine.

### 3.1 Goals

- Produce readable text for simple HTML pages.
- Preserve link targets with numbering.
- Avoid huge memory usage: fixed buffers and explicit caps.

### 3.2 Supported subset (v0)

Text emission:

- Drop tags, render text content.
- Collapse whitespace outside `<pre>`.

Block-ish tags that affect spacing:

- `p`, `div`: ensure blank line separation (or at least newline).
- `br`: newline.
- `h1..h6`: newline before/after.
- `ul/ol/li`: bulleting with `- `; indent based on nesting depth (capped).
- `pre`: preserve newlines and spaces verbatim until `</pre>`.

Ignored/skipped content:

- `<script>…</script>`
- `<style>…</style>`

### 3.3 Entities

Implement a small set of HTML entity decoding:

- Named: `&lt; &gt; &amp; &quot; &apos;`
- Numeric: `&#NN;` and `&#xNN;`

Unknown entities should be left as-is or replaced with `?` (pick one and document).

### 3.4 Links and numbering

When encountering `<a href="…">`:

- Capture the href value (bounded cap, e.g. 2048 bytes).
- During rendering, append a link marker after the anchor text, e.g. `Text[12]`.

At the end of rendering:

- Print a `Links:` section listing `N URL`.

### 3.5 Relative URL resolution

Resolve a captured href against the current page URL.

Rules (v0):

- If href begins with `http://` or `https://`: absolute.
- If href begins with `/`: same scheme/host/port, new path.
- Otherwise: join with the “directory” of the current path.
  - Example: base `/a/b/index.html` + `c.html` → `/a/b/c.html`

Do not implement `..` normalization initially unless it is needed for real sites; if implemented, cap the work and reject escaping above `/`.

---

## 4) User interaction plan

No curses in v0. Keep it robust and scriptable.

### 4.1 Interactive command loop

In `-i` mode:

- Fetch+render page.
- Display via a pager-like flow.
- Read commands from `/dev/tty` line-by-line.

Commands:

- `go N` — follow link N
- `open URL` — open a new URL
- `back` — go to previous page in history
- `links` — print link table
- `reload` — refetch current URL
- `quit`

### 4.2 History model

- Fixed-cap stack (e.g. 32 entries).
- Each entry stores URL and (optionally) resolved link table.

### 4.3 Pager behavior

Re-use the spirit of `more`:

- 24 lines per “page”
- prompt `--More--` on stderr
- quit with `q`

Implementation choices (v0):

- Either:
  - render into a temp file under a known writable directory (e.g. `/tmp`) then page it, or
  - page directly while rendering (harder if we want to print Links at the end).

For testability, dump mode should remain the primary output contract.

---

## 5) Work packages (testable milestones)

This project should be delivered as small, testable packages.

### WP0 — Document + CLI skeleton

Deliverables:

- `docs/browser.md` (this doc)
- `tools/browse.c` skeleton with:
  - usage/help
  - argument parsing
  - exit code discipline

Tests:

- Tools smoke suite:
  - `browse --help` exits `0` or `2` depending on convention (prefer `2` for “usage shown” if that’s what `mc_die_usage` does).
  - invalid args → exit `2`.

### WP1 — HTML renderer (offline)

Deliverables:

- HTML tokenizer + renderer producing:
  - rendered text
  - link table
- No networking yet: read HTML from stdin or a file.

CLI for this stage (temporary or kept):

- `browse --render-html FILE` (or `browse --render-html < file`)

Tests:

- Add fixtures under `tests/data/html/`:
  - `basic.html` with `<p>`, `<br>`, `<a href>`
  - `lists.html` with nested `<ul><li>`
  - `pre.html` with `<pre>` spacing
  - `entities.html` with entity decoding
- Golden outputs:
  - `basic.txt`, etc.
- Assertions should be conservative (exact text match is ok for fixtures).

### WP2 — HTTP fetch (http://) + content-type

Deliverables:

- HTTP fetch implementation (derived from `wget6` patterns)
- Feed response body into the renderer
- Detect HTML vs plain text:
  - If `Content-Type` begins with `text/html`: render as HTML
  - Else: treat as plain text and still allow link extraction to be empty

Tests:

- Avoid live internet.
- Option A: add a tiny in-test HTTP server only if the harness already supports it.
- Option B (preferred initially): keep networking untested and focus on renderer tests, but add unit-style tests for:
  - URL parsing
  - header parsing
  - chunked decoder

### WP3 — Redirects + relative URL resolution

Deliverables:

- Follow redirects (max depth)
- Relative href resolution integrated into link table

Tests:

- Unit tests for redirect resolution and URL join logic.
- HTML fixtures with relative hrefs; validate resolved URLs.

### WP4 — HTTPS fetch (optional for v0, but high value)

Deliverables:

- In-process HTTPS fetch using TLS core (based on `tls13 hs`, without debug output)

Tests:

- Offline: unit tests for URL parsing and request building.
- Optional: a controlled HTTPS endpoint is hard without adding infra; keep any live test as “manual smoke” only.

### WP5 — Interactive mode

Deliverables:

- `browse -i URL` loop with `go/open/back/links/reload/quit`
- Pager output using `/dev/tty`

Tests:

- Keep interaction tests minimal.
- Prefer testing command parsing as pure functions.
- Manual smoke test inside VM is acceptable for interactive UX.

---

## 6) Non-goals (explicit)

- JavaScript execution
- CSS layout
- Cookies/session/auth
- Forms
- Image rendering
- Full HTML correctness
- Certificate validation (until we have X.509 parsing)

---

## 7) References in tree

- HTTP (IPv6-only) implementation patterns: `tools/wget6.c`
- TLS 1.3 implementation: `tools/tls13.c` and `core/mc_tls13*.c`
- Pager input style: `tools/more.c`
- TLS scope and limitations: `docs/tls.md`
