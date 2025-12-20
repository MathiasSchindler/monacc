# Text-mode web browser (monacc)

Date: 2025-12-20

This document specifies (and tracks) a minimalist, syscall-only, text-mode web browser for monacc.

The goal is *not* to re-create a full `lynx`/`links`, but to get a useful “debugging browser” for the monacc VM:

- Fetch `http(s)://…` pages
- Render a readable text approximation
- Extract and list links
- Follow links interactively (planned; WP5)

Constraints: same as the rest of monacc tools:

- syscall-only (no libc)
- stable-ish text output
- small, explicit feature subset
- consistent exit codes: `0` success, `1` operational error, `2` usage error

---

## Status (today)

Implemented (WP0–WP4 complete):

- `browse URL` fetches and renders `http://` and `https://` URLs (IPv6-only).
- Redirects: follows `301/302/303/307/308` up to depth 5, resolves relative `Location:`.
- HTML → text renderer (streaming, no DOM) with link markers `Text[N]` and a trailing `Links:` table.
- Deterministic helper modes for tests: `--render-html`, `--render-html-base`, `--parse-url`, `--resolve-url`, `--parse-http-headers`, `--decode-chunked`.
- HTTPS uses in-process TLS 1.3; **no certificate validation**.

Not implemented yet (WP5): interactive/pager mode.

---

## 1) Scope and CLI

### 1.1 Tool name

Tool: `browse`.

### 1.2 Modes

- Dump mode (default): fetch + render to stdout.
- Link-table mode: fetch + print only the trailing `Links:` table.
- Offline/deterministic helpers: HTML rendering and parsers used by tests.
- Interactive mode is planned (WP5) but not implemented.

### 1.3 CLI (current)

- `browse URL`
- `browse -dump-links URL`
- `browse --render-html FILE|-`
- `browse --render-html-base BASE_URL FILE|-`
- `browse --parse-url URL`
- `browse --resolve-url BASE_URL HREF`
- `browse --parse-http-headers < headers.txt`
- `browse --decode-chunked < chunked.txt`

Notes:
- URL grammar is intentionally small and strict.
- Automated tests avoid the live internet; networking is validated manually.

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

(For relative URLs, `browse` prints resolved absolute URLs in the Links section.)

---

## 2) Networking implementation (fetch layer)

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

### 2.3 HTTP/1.1 over TCP (`http://`)

Implementation approach:

- Use `wget6` patterns:
  - connect timeout via non-blocking socket + `poll`
  - send `GET` with `Host:` and `Connection: close`
  - parse status line and headers
  - decode body for:
    - `Content-Length`
    - `Transfer-Encoding: chunked`

Behavior:

- Non-2xx (except redirects) is an operational failure (`exit 1`).

### 2.4 Redirects

Needed for real browsing.

Redirect handling:

- Follow `301/302/303/307/308` when `Location:` is present.
- Resolve `Location`:
  - absolute URL: `http(s)://…`
  - absolute path: `/…` (same scheme/host/port)

Cap:

- max depth 5, then fail.

### 2.5 HTTPS (`https://`)

We already have a TLS 1.3 implementation (see docs/tls.md). For browsing, we want an internal API to “GET over TLS”.

Implemented: in-process TLS 1.3 fetch.

- Uses SNI.
- Sends the HTTP request as application data and decrypts the response stream.
- Quiet by default (no handshake debug spew).

Security note (must be documented in tool `--help` and in this doc):

- **No certificate validation** (no X.509). HTTPS is encrypted but not authenticated.

---

## 3) HTML → text rendering

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

Implemented: relative join + dot-segment normalization with a fixed-cap implementation.

---

## 4) User interaction (planned)

No curses in v0. Keep it robust and scriptable.

### 4.1 Interactive command loop

In `-i` mode (WP5):

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

### WP0 — Document + CLI skeleton (done)

- Implemented in `tools/browse.c`; covered by `browse --help`, invalid-args smoke tests.

### WP1 — HTML renderer (offline) (done)

- `browse --render-html FILE|-` renders fixtures deterministically; golden outputs live under `tests/tools/data/html/`.

### WP2 — HTTP fetch (`http://`) + deterministic helpers (done)

- Fetcher: IPv6-only DNS AAAA + TCP connect with timeout; HTTP/1.1 GET; header parsing; `Content-Length` and `chunked` body streaming.
- Deterministic helper modes are covered by fixtures under `tests/tools/data/http/`.

### WP3 — Redirects + relative URL resolution (done)

- Redirect loop (max depth 5) and URL resolution are implemented and exercised via `--resolve-url` and `--render-html-base` fixtures.

### WP4 — HTTPS fetch (done)

- In-process TLS 1.3 fetch is integrated into `browse URL` for `https://…` (no certificate validation).
- Offline coverage: URL parsing fixtures include `https://` defaults; live fetch remains manual-only.

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
