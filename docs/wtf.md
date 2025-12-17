# wtf — Wikipedia Terminal Facts

Date: 2025-12-17

**"What the Fact?"** — A command-line tool for querying Wikipedia and displaying article summaries in plain text.

---

## Rationale

### Why This Tool?

`wtf` fills a gap in the monacc toolset: **quick access to encyclopedic knowledge from the terminal**. It demonstrates monacc's networking capabilities while providing genuine utility.

| Aspect | Value |
|--------|-------|
| **Practical** | Instant fact lookup without leaving the terminal |
| **Educational** | Exercises HTTP, DNS, and JSON parsing over IPv6 |
| **Unix-like** | Simple tool, one job, text output, pipeable |
| **Memorable** | `wtf caffeine` is delightful to type |

### Name

- **wtf** — "What the Fact?" (for concepts and things)
- Also works as "Who the Fact?" (for people)
- Short, memorable, fits the Unix tradition of terse command names

### Design Philosophy Alignment

| Principle | How `wtf` Follows It |
|-----------|---------------------|
| **Syscalls only** | Uses existing `mc_net.h` infrastructure; no libc networking |
| **No third-party software** | Implements HTTP client and JSON parsing in-tree |
| **Single platform** | IPv6-only, Linux x86_64 |
| **C language** | Implemented in C using monacc's supported subset |
| **Self-contained** | Builds with monacc's internal toolchain |

### Priority Order

1. **Working** — Correct output for common queries
2. **Small** — Minimal binary size; reuse existing infrastructure
3. **Fast** — Performance is secondary; network latency dominates anyway

---

## Usage

```bash
# Basic usage: query English Wikipedia
wtf caffeine

# Query a specific language Wikipedia
wtf -l de Koffein
wtf -l fr Caféine

# First sentence only (short mode)
wtf -s caffeine

# Combine flags
wtf -l de -s Koffein

# Person lookup
wtf "Albert Einstein"

# Multi-word queries (quoted or concatenated with underscores)
wtf "central nervous system"
wtf central_nervous_system
```

### Output

```
$ wtf caffeine
Caffeine is a central nervous system (CNS) stimulant of the methylxanthine
class and is the most commonly consumed psychoactive substance globally...

$ wtf -s caffeine
Caffeine is a central nervous system (CNS) stimulant of the methylxanthine class and is the most commonly consumed psychoactive substance globally.

$ wtf -l de Koffein
Koffein ist ein Alkaloid aus der Stoffgruppe der Xanthine...
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success; article found and printed |
| 1 | Article not found (even after search fallback) |
| 2 | Usage error (invalid flags, missing query) |

---

## Technical Design

### Wikipedia API Endpoints

Wikipedia provides two relevant API mechanisms:

#### 1. Page Summary (Primary)

```
https://{lang}.wikipedia.org/api/rest_v1/page/summary/{title}
```

**Response (JSON):**
```json
{
  "title": "Caffeine",
  "extract": "Caffeine is a central nervous system...",
  "description": "chemical compound"
}
```

- Returns plain text summary in `extract` field
- Fast, lightweight endpoint
- Handles redirects automatically

#### 2. OpenSearch (Fallback for "not found")

```
https://{lang}.wikipedia.org/w/api.php?action=opensearch&search={query}&limit=1&format=json
```

**Response (JSON array):**
```json
[
  "caffeine",
  ["Caffeine"],
  ["Caffeine is a central nervous system..."],
  ["https://en.wikipedia.org/wiki/Caffeine"]
]
```

- Used when direct title lookup fails
- Returns best-matching article title
- Then fetch that title via the summary endpoint

### Request Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  wtf "central nervous system"                                   │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. URL-encode query: "central%20nervous%20system"              │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. DNS lookup: en.wikipedia.org → AAAA record (IPv6)           │
│     (reuse dns6 infrastructure)                                 │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. TCP connect to [IPv6]:443 (HTTPS) or :80 (HTTP)             │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. HTTP GET /api/rest_v1/page/summary/central%20nervous%20system│
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
                 ┌──────────┴──────────┐
                 │                     │
            HTTP 200               HTTP 404
                 │                     │
                 ▼                     ▼
┌────────────────────────┐  ┌─────────────────────────────────────┐
│ Parse JSON, extract    │  │ 5. Fallback: OpenSearch API         │
│ "extract" field        │  │    GET /w/api.php?action=opensearch │
└────────────────────────┘  └─────────────────────────────────────┘
                 │                     │
                 │              ┌──────┴──────┐
                 │              │             │
                 │         Found title    No results
                 │              │             │
                 │              ▼             ▼
                 │    ┌─────────────────┐  ┌──────────┐
                 │    │ Retry summary   │  │ Exit 1   │
                 │    │ with found title│  └──────────┘
                 │    └─────────────────┘
                 │              │
                 ▼              ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. Print extract to stdout                                     │
│     (If -s: truncate at first ". ")                             │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
                        Exit 0
```

### HTTPS Challenge

Wikipedia enforces HTTPS. In practice, Wikipedia currently redirects plain HTTP to HTTPS (e.g. `http://en.wikipedia.org/w/api.php?...` → `301` with `Location: https://...`).

**Implication:** A syscall-only HTTP client (like `wget6`) cannot fetch Wikipedia API responses reliably until monacc gains TLS client support.

Options:

| Option | Pros | Cons |
|--------|------|------|
| **A. Implement TLS** | Full compatibility; unblocks `wtf`, `wget6`, future net tools | Significant work (see `docs/tls.md`) |
| **B. Follow HTTP redirect** | Small change if redirect stays same-host | Still requires HTTPS after redirect → TLS needed anyway |
| **C. Use HTTP API** | Simplest client-side | Not viable if endpoints redirect to HTTPS |

**Recommended approach:** Implement Option A (TLS 1.3 client) first, then build `wtf` on top of HTTPS.

`wtf` can still be developed incrementally without TLS by:
- implementing parsing/formatting logic against recorded JSON responses (fixtures), and
- optionally shipping an early version that prints a stable error like: `wtf: HTTPS required (TLS not implemented)`.

### IPv6 Only

Following monacc's networking philosophy (see `wget6.c`, `dns6.c`):

- DNS resolution via AAAA records only
- TCP connections over IPv6
- Falls back to Google Public DNS (`2001:4860:4860::8888`) if no IPv6 nameserver in `/etc/resolv.conf`

---

## Implementation Plan

### Prerequisite: HTTPS Support

`wtf` depends on HTTPS access to Wikipedia endpoints. Implement TLS first (see `docs/tls.md`), then build `wtf` on top of a shared `mc_tls` API that can back `wget6` and future tools.

### Phase 0: Preparation

#### 0.1 Study Existing Infrastructure

Review and understand:
- `tools/wget6.c` — HTTP client, will reuse patterns
- `tools/dns6.c` — DNS resolution
- `core/mc_net.h` — Networking primitives

**Key functions to reuse:**
```c
// From wget6.c:
static int parse_http_url(...)           // URL parsing
static int dns6_resolve_first_aaaa(...)  // DNS lookup
static mc_i64 read_line(...)             // HTTP response reading

// From dns6.c:
static int parse_ipv6_literal(...)       // IPv6 parsing
static int resolv_conf_pick_v6(...)      // Find DNS server
```

#### 0.2 Create Shared Networking Header (Optional)

Consider extracting common networking code into `core/mc_net_util.c`:
- `dns6_resolve()` 
- `http_get()`
- URL encoding

**Decision:** For now, duplicate code in `wtf.c` (following existing tool patterns). Refactor later if more tools need it.

---

### Phase 1: Core Implementation

#### 1.1 Create `tools/wtf.c` Skeleton

```c
#include "mc.h"
#include "mc_net.h"

// --- URL encoding ---
static int url_encode(const char *in, char *out, mc_usize cap);

// --- JSON parsing (minimal) ---
static int json_extract_string(const char *json, const char *key, 
                               char *out, mc_usize cap);

// --- HTTP request/response ---
static int http_get(const char *host, mc_u16 port, const char *path,
                    char *response, mc_usize cap);

// --- Wikipedia API ---
static int wiki_get_summary(const char *lang, const char *title,
                            char *out, mc_usize cap);
static int wiki_search(const char *lang, const char *query,
                       char *out_title, mc_usize cap);

// --- Main ---
int main(int argc, char **argv, char **envp);
```

#### 1.2 Argument Parsing

```c
// Flags:
//   -l LANG    Language code (default: "en")
//   -s         Short mode (first sentence only)
//   --         End of options
//   QUERY...   Search terms (joined with spaces or underscores)

typedef struct {
    const char *lang;      // "en", "de", "fr", etc.
    int short_mode;        // -s flag
    char query[256];       // URL-encoded query
} WtfOptions;

static int parse_args(int argc, char **argv, WtfOptions *opts);
```

#### 1.3 URL Encoding

```c
// Encode spaces as %20, other special chars as %XX
// Safe chars: A-Z a-z 0-9 - _ . ~
static int url_encode(const char *in, char *out, mc_usize cap) {
    static const char hex[] = "0123456789ABCDEF";
    mc_usize j = 0;
    for (mc_usize i = 0; in[i]; i++) {
        unsigned char c = (unsigned char)in[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || 
            c == '.' || c == '~') {
            if (j + 1 >= cap) return 0;
            out[j++] = (char)c;
        } else {
            if (j + 3 >= cap) return 0;
            out[j++] = '%';
            out[j++] = hex[(c >> 4) & 0xF];
            out[j++] = hex[c & 0xF];
        }
    }
    out[j] = 0;
    return 1;
}
```

#### 1.4 Minimal JSON Parsing

We only need to extract string values by key. No need for a full parser.

```c
// Find "key":"value" and extract value (handling escaped quotes)
static int json_extract_string(const char *json, const char *key,
                               char *out, mc_usize cap) {
    // Build search pattern: "key":"
    char pattern[64];
    mc_usize plen = 0;
    pattern[plen++] = '"';
    for (mc_usize i = 0; key[i] && plen < 60; i++) {
        pattern[plen++] = key[i];
    }
    pattern[plen++] = '"';
    pattern[plen++] = ':';
    pattern[plen] = 0;
    
    // Find pattern in json
    const char *p = json;
    while (*p) {
        const char *match = p;
        mc_usize i;
        for (i = 0; pattern[i]; i++) {
            if (match[i] != pattern[i]) break;
        }
        if (pattern[i] == 0) {
            // Found key, now extract value
            p = match + plen;
            // Skip whitespace
            while (*p == ' ' || *p == '\t' || *p == '\n') p++;
            if (*p != '"') return 0;
            p++; // skip opening quote
            
            mc_usize j = 0;
            while (*p && *p != '"') {
                if (*p == '\\' && p[1]) {
                    p++; // skip backslash
                    char c = *p++;
                    if (c == 'n') c = '\n';
                    else if (c == 't') c = '\t';
                    else if (c == 'r') c = '\r';
                    // else keep char as-is (handles \", \\, etc.)
                    if (j + 1 < cap) out[j++] = c;
                } else {
                    if (j + 1 < cap) out[j++] = *p;
                    p++;
                }
            }
            out[j] = 0;
            return 1;
        }
        p++;
    }
    return 0;
}
```

#### 1.5 HTTP GET (Reuse wget6 Patterns)

```c
// Simplified HTTP GET, returns response body
// Reuses wget6 patterns for connection, request, response parsing
static int http_get(const char *argv0, const char *host, 
                    const mc_u8 ip6[16], mc_u16 port, const char *path,
                    char *response, mc_usize cap, int *out_status) {
    // 1. TCP connect (from wget6)
    // 2. Send: GET {path} HTTP/1.1\r\nHost: {host}\r\n...
    // 3. Read response headers, check status
    // 4. Read body into response buffer
    // 5. Return success/failure
}
```

---

### Phase 2: Wikipedia Integration

#### 2.1 Summary Endpoint

```c
static int wiki_get_summary(const char *argv0, const char *lang, 
                            const char *title, char *out, mc_usize cap) {
    // 1. Build hostname: "{lang}.wikipedia.org"
    char host[64];
    mc_snprintf(host, sizeof(host), "%s.wikipedia.org", lang);
    
    // 2. DNS resolve
    mc_u8 ip6[16];
    if (!dns6_resolve_aaaa(host, ip6)) return -1;
    
    // 3. Build path: "/api/rest_v1/page/summary/{title}"
    char path[512];
    char encoded_title[256];
    url_encode(title, encoded_title, sizeof(encoded_title));
    mc_snprintf(path, sizeof(path), 
                "/api/rest_v1/page/summary/%s", encoded_title);
    
    // 4. HTTP GET
    char response[32768];
    int status = 0;
    if (!http_get(argv0, host, ip6, 80, path, response, 
                  sizeof(response), &status)) {
        return -1;
    }
    
    // 5. Check status
    if (status == 404) return 0;  // Not found, try search
    if (status != 200) return -1; // Error
    
    // 6. Extract "extract" field from JSON
    if (!json_extract_string(response, "extract", out, cap)) {
        return -1;
    }
    
    return 1; // Success
}
```

#### 2.2 Search Fallback

```c
static int wiki_search(const char *argv0, const char *lang,
                       const char *query, char *out_title, mc_usize cap) {
    // 1. Build path: "/w/api.php?action=opensearch&search={query}&limit=1&format=json"
    char path[512];
    char encoded[256];
    url_encode(query, encoded, sizeof(encoded));
    mc_snprintf(path, sizeof(path),
                "/w/api.php?action=opensearch&search=%s&limit=1&format=json",
                encoded);
    
    // 2. HTTP GET
    char response[4096];
    int status = 0;
    // ... same as above ...
    
    // 3. Parse OpenSearch response
    // Response format: ["query", ["Title1"], ["Desc1"], ["URL1"]]
    // Extract first title from second array
    // ... minimal parsing ...
    
    return found ? 1 : 0;
}
```

#### 2.3 Main Logic

```c
int main(int argc, char **argv, char **envp) {
    (void)envp;
    const char *argv0 = argv[0] ? argv[0] : "wtf";
    
    WtfOptions opts = {0};
    opts.lang = "en";
    if (!parse_args(argc, argv, &opts)) {
        return 2; // Usage error
    }
    
    char extract[32768];
    
    // Try direct lookup first
    int rc = wiki_get_summary(argv0, opts.lang, opts.query, 
                              extract, sizeof(extract));
    
    if (rc == 0) {
        // Not found, try search
        char found_title[256];
        if (wiki_search(argv0, opts.lang, opts.query, 
                        found_title, sizeof(found_title))) {
            rc = wiki_get_summary(argv0, opts.lang, found_title,
                                  extract, sizeof(extract));
        }
    }
    
    if (rc <= 0) {
        mc_write_str(2, argv0);
        mc_write_str(2, ": not found\n");
        return 1;
    }
    
    // Short mode: truncate at first sentence
    if (opts.short_mode) {
        char *dot = extract;
        while (*dot) {
            if (*dot == '.' && (dot[1] == ' ' || dot[1] == '\n' || dot[1] == 0)) {
                dot[1] = '\n';
                dot[2] = 0;
                break;
            }
            dot++;
        }
    }
    
    // Output
    mc_write_str(1, extract);
    mc_write_str(1, "\n");
    
    return 0;
}
```

---

### Phase 3: Refinements

#### 3.1 Handle Multi-Word Queries

```c
// Join argv arguments with underscores (Wikipedia convention)
// "Albert" "Einstein" → "Albert_Einstein"
static void join_query(int argc, char **argv, int start, 
                       char *out, mc_usize cap) {
    mc_usize n = 0;
    for (int i = start; i < argc && argv[i]; i++) {
        if (i > start && n + 1 < cap) out[n++] = '_';
        for (const char *p = argv[i]; *p && n + 1 < cap; p++) {
            out[n++] = (*p == ' ') ? '_' : *p;
        }
    }
    out[n] = 0;
}
```

#### 3.2 User-Agent Header

Be a good citizen:
```c
write_all(fd, "User-Agent: monacc-wtf/1.0 (https://github.com/MathiasSchindler/monacc)\r\n", ...);
```

#### 3.3 Timeout Handling

Reuse `wget6` timeout patterns:
```c
// Default 5 second timeout for DNS and HTTP
mc_u32 timeout_ms = 5000;
```

---

## Testing

### Manual Tests

```bash
# Basic functionality
./bin/wtf caffeine
./bin/wtf "Albert Einstein"
./bin/wtf Linux

# Language support
./bin/wtf -l de Deutschland
./bin/wtf -l fr France

# Short mode
./bin/wtf -s caffeine

# Edge cases
./bin/wtf ""                    # Should exit 2
./bin/wtf xyznonexistent123     # Should exit 1, try search fallback
./bin/wtf "United States"       # Multi-word
```

### Automated Tests

Add to `tests/suites/smoke.d/`:
```bash
# wtf smoke test (requires network)
if bin/wtf caffeine | grep -q "stimulant"; then
    echo "wtf: ok"
else
    echo "wtf: FAIL"
    exit 1
fi
```

---

## Size Estimate

| Component | Lines | Notes |
|-----------|-------|-------|
| Argument parsing | ~60 | -l, -s flags, query joining |
| URL encoding | ~30 | Simple percent-encoding |
| JSON parsing | ~60 | Minimal key-value extraction |
| DNS resolution | ~50 | Mostly reused from wget6 |
| HTTP client | ~150 | Simplified from wget6 |
| Wikipedia API | ~80 | Summary + search |
| Main logic | ~50 | Flow control, output |
| **Total** | ~480 | Comparable to other tools |

---

## Future Enhancements

### If HTTP is Blocked

Add TLS support. This would be a significant addition (~1000+ lines) but valuable for the entire monacc ecosystem. Could be implemented as:
- `core/mc_tls.c` — Minimal TLS 1.2/1.3 client
- Used by `wtf`, `wget6`, and future HTTPS tools

### Additional Features

| Feature | Complexity | Value |
|---------|------------|-------|
| `-v` verbose mode | Low | Show HTTP headers, timing |
| `-r` raw JSON | Low | Output full API response |
| `-u` URL output | Low | Print Wikipedia URL instead |
| Cache | Medium | Store recent lookups locally |
| Disambiguation | Medium | Handle Wikipedia disambiguation pages |

---

## Appendix: Wikipedia Language Codes

Common codes for `-l` flag:

| Code | Language |
|------|----------|
| `en` | English (default) |
| `de` | German |
| `fr` | French |
| `es` | Spanish |
| `it` | Italian |
| `pt` | Portuguese |
| `ru` | Russian |
| `ja` | Japanese |
| `zh` | Chinese |
| `ar` | Arabic |

Full list: https://meta.wikimedia.org/wiki/List_of_Wikipedias

---

## Appendix: API Response Examples

### Page Summary (Success)

```json
{
  "type": "standard",
  "title": "Caffeine",
  "displaytitle": "Caffeine",
  "namespace": { "id": 0, "text": "" },
  "wikibase_item": "Q60235",
  "titles": {
    "canonical": "Caffeine",
    "normalized": "Caffeine",
    "display": "Caffeine"
  },
  "extract": "Caffeine is a central nervous system (CNS) stimulant...",
  "extract_html": "<p><b>Caffeine</b> is a central nervous system...",
  "description": "chemical compound",
  "description_source": "local"
}
```

### OpenSearch (Success)

```json
[
  "caffeine",
  ["Caffeine", "Caffeine (disambiguation)", "Caffeine and breastfeeding"],
  ["", "", ""],
  [
    "https://en.wikipedia.org/wiki/Caffeine",
    "https://en.wikipedia.org/wiki/Caffeine_(disambiguation)",
    "https://en.wikipedia.org/wiki/Caffeine_and_breastfeeding"
  ]
]
```

### Page Summary (Not Found)

```json
{
  "type": "https://mediawiki.org/wiki/HyperSwitch/errors/not_found",
  "title": "Not found.",
  "method": "get",
  "detail": "Page or revision not found.",
  "uri": "/en.wikipedia.org/v1/page/summary/Xyznonexistent"
}
```
