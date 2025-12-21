# Mastodon CLI — Implementation Plan

A command-line client for Mastodon, built with monacc. Supports reading timelines and posting statuses.

---

## Overview

This is a complex tool requiring:
- **HTTPS/TLS 1.3** — Mastodon API is HTTPS-only (we have `mc_tls13.c`)
- **JSON parsing** — API responses are JSON (needs a minimal parser)
- **OAuth 2.0 authentication** — posting requires user tokens
- **HTTP/1.1 client** — constructing REST requests over TLS

The implementation is split into **incremental phases** to keep each step testable.

---

## Implementation Status (as of 2025-12-21)

This document started as a plan; the tool is now largely implemented.

**Implemented**
- Commands: `ping`, `instance`, `raw PATH`, `public` (local/federated), `home`, `notif`, `post`
- HTTPS/TLS 1.3: uses in-tree TLS directly (no runtime dependency on a separate `tls13` tool)
- DNS: in-tool minimal AAAA resolver (IPv6-first), no `dns6` dependency
- HTTP: status-line parsing, body extraction, and `Transfer-Encoding: chunked` decoding
- JSON: array/object walking; string extraction with unescaping + ASCII `\uXXXX` decoding; integer (`u64`) extraction for counters
- Output: status `display_name`, stripped `content`, and counts (boosts/favs/replies)

**Partially implemented / limitations**
- No certificate validation (TOFU/CA validation not implemented)
- IPv6 AAAA-only name resolution (no A/IPv4 fallback)
- Fixed-size buffers (very large responses may fail)

**Not implemented (yet)**
- Phase 8 interactive TUI mode
- Streaming API (`/api/v1/streaming/user`)

---

## Phase 1: Configuration via Environment & CLI

**Goal:** Accept instance and token via environment variables and CLI flags.

### Usage
```bash
TOKEN=xxx masto --instance gruene.social home
TOKEN=xxx masto -i gruene.social post "Hello!"
```

### Environment variables
- `TOKEN` — Mastodon access token (required for authenticated endpoints)
- `INSTANCE` — default instance if `--instance` not provided (optional)

### CLI flags
- `--instance HOST` / `-i HOST` — Mastodon instance hostname (e.g. `gruene.social`)

### Implementation
- Read `TOKEN` via `mc_getenv()` or parse from `envp`
- Parse `--instance` / `-i` from argv
- No config file needed — simpler, no file I/O

### Token acquisition
Users obtain a token via their instance's web UI:
`Preferences → Development → New Application → copy access token`

### Example wrapper script (optional convenience)
```bash
#!/bin/sh
# ~/bin/toot
export TOKEN="your-token-here"
exec masto --instance gruene.social "$@"
```

---

## Phase 2: DNS & TCP/TLS Connection

**Goal:** Establish a TLS 1.3 connection to the Mastodon instance.

### Dependencies (already in-tree)
- `mc_tls13.c` — TLS 1.3 handshake + record layer
- `mc_x25519.c` — key exchange
- `mc_aes.c` / `mc_gcm.c` — encryption
- `mc_sha256.c` / `mc_hkdf.c` — key derivation

### Notes
- The current implementation does DNS resolution and TCP connect internally (no runtime dependency on `dns6`/`tcp6`).

### Implementation
- Resolve hostname (AAAA) via internal DNS client
- Open TCP socket to port 443
- Perform TLS 1.3 handshake via `mc_tls13_client_*`

### Test
```
masto ping    # verify TLS connection works
```

---

## Phase 3: HTTP/1.1 Client

**Goal:** Send HTTP requests over TLS and receive responses.

### HTTP request format
```
GET /api/v1/timelines/home HTTP/1.1
Host: mastodon.social
Authorization: Bearer <token>
Accept: application/json
Connection: close

```

### Implementation
- `masto_http.c` — build HTTP request, send over TLS, read response
- Parse HTTP status line (`HTTP/1.1 200 OK`)
- Handle `Content-Length` or `Transfer-Encoding: chunked`
- Extract JSON body

---

## Phase 4: Minimal JSON Parser

**Goal:** Parse Mastodon API JSON responses.

### What we need (practical requirements)

Mastodon API responses are JSON, and for timelines/notifications we need to reliably extract a handful of fields from nested objects/arrays without depending on libc or heap allocation.

**Required capabilities**
- **Arrays of objects:** timelines are `[{...}, {...}]` and notifications are `[{...}, ...]`.
- **Nested objects:** e.g. `account` object inside a status (`account.acct`, `account.display_name`).
- **JSON strings with escapes:** handle `\\`, `\"`, `\n`, etc.
- **Unicode escapes in strings:** Mastodon often returns HTML in JSON using `\u003c`/`\u003e` (`<`/`>`). We must at least decode **ASCII-range** `\uXXXX` so HTML stripping works.
- **Null/booleans/numbers:** we don’t need to interpret all numeric fields, but we must be able to skip them while walking.

**Non-goals (for early phases)**
- Full JSONPath / query language.
- Full Unicode handling (surrogates, UTF-16 decoding). For now: decode ASCII `\uXXXX`, map non-ASCII to `?` or leave as UTF-8 if already present.
- Perfect schema validation.

### Constraints (project-specific)
- **No malloc**: fixed-size output buffers and stack-local state.
- **Truncation is OK**: if a string exceeds the destination buffer, truncate safely and still produce valid output.
- **Streaming-friendly**: allow scanning large JSON blobs with simple state (no need to build a DOM).
- **Robust skipping**: the parser must tolerate unknown fields and skip values we don’t care about.

### Suggested API surface

For the CLI phases, we get the most leverage from a tiny “scanner + helpers” API:
- `masto_json_next_object_in_array(...)` — iterate top-level `{...}` objects inside an array without parsing everything.
- `masto_json_find_object_field(...)` — find `"account":{...}` and return a slice of that nested object.
- `masto_json_get_string_field(...)` — extract a string field (`"created_at":"..."`, `"content":"..."`, ...), including JSON unescaping and ASCII `\uXXXX` decoding.

This is enough for Phase 5 (timeline output) and Phase 7 (notifications) without committing to a full recursive-descent parser.

### Needed JSON operations
- Parse arrays of objects (timeline = array of statuses)
- Extract string fields: `id`, `content`, `created_at`, `account.username`, `account.display_name`
- Handle HTML content (strip `<p>`, `<br>`, `<a>` tags for display)

### Implementation
- `masto_json.c` — minimal JSON scanner + helpers (no heap)
- Only parse what we need (ignore unknown fields)
- Use fixed buffers, tolerate truncation, decode ASCII `\uXXXX` in strings

### Data structures
```c
struct masto_status {
    char id[32];
    char username[64];
    char display_name[128];
    char content[2048];       // HTML stripped to plain text
    char created_at[32];
};
```

---

## Phase 5: Read Timeline

**Goal:** Fetch and display home timeline.

### API Endpoint
```
GET /api/v1/timelines/home
Authorization: Bearer <token>
```

Returns array of Status objects.

### CLI commands
```
masto home              # show home timeline (default 20 posts)
masto home -n 5         # show 5 most recent posts
masto public            # show local public timeline
masto public -r         # show federated (remote) public timeline
```

### Output format
```
@username@instance.social · 2h ago
Display Name
This is the status content with HTML tags stripped.
Boosts: 5 · Favs: 12 · Replies: 3
────────────────────────────────────
```

---

## Phase 6: Post Status

**Goal:** Post a new status to Mastodon.

### API Endpoint
```
POST /api/v1/statuses
Authorization: Bearer <token>
Content-Type: application/x-www-form-urlencoded

status=Hello+world!
```

### CLI commands
```
masto post "Hello, world!"              # post a public status
masto post -u "Unlisted post"           # unlisted visibility
masto post -p "Private post"            # followers-only
masto post -d "@user Private message"   # direct message
masto post -s "CW" "Content warning"    # with content warning
```

### Form encoding
- URL-encode special characters (`%20` for space, etc.)
- Set `visibility` parameter: `public`, `unlisted`, `private`, `direct`
- Set `spoiler_text` for content warnings

---

## Phase 7: Notifications

**Goal:** View recent notifications.

### API Endpoint
```
GET /api/v1/notifications
Authorization: Bearer <token>
```

### CLI commands
```
masto notif             # show recent notifications
masto notif -n 10       # show 10 notifications
```

### Notification types
- `mention` — someone mentioned you
- `reblog` — someone boosted your post  
- `favourite` — someone favourited your post
- `follow` — someone followed you

---

## Phase 8 (Optional): Interactive TUI Mode

**Goal:** Full-screen terminal app with live timeline and command input.

### Layout
```
┌─────────────────────────────────────────────────────────┐
│ Home Timeline                          ↻ 30s ago       │
├─────────────────────────────────────────────────────────┤
│ @gargron@mastodon.social · 2m ago                       │
│ Eugen Rochko                                            │
│ Check out the new Mastodon 4.3 release!                 │
│ ↺ 234 · ★ 891 · ↩ 45                                    │
│─────────────────────────────────────────────────────────│
│ @user@instance · 15m ago                                │
│ Another User                                            │
│ This is another post in the timeline...                 │
│ ↺ 12 · ★ 45 · ↩ 3                                       │
│─────────────────────────────────────────────────────────│
│                                                         │
│                      (more posts)                       │
│                                                         │
├─────────────────────────────────────────────────────────┤
│ > _                                                     │
└─────────────────────────────────────────────────────────┘
```

### Features
- **Timeline view** — scrollable, shows home timeline (upper 80% of screen)
- **Status bar** — shows last refresh time, instance name
- **Command line** — bottom of screen for input

### Commands in interactive mode
```
> Hello world!              # post a status
> /r                        # refresh timeline now
> /n                        # switch to notifications view
> /h                        # switch to home timeline
> /p                        # switch to public timeline  
> /q                        # quit
> /reply 12345 Thanks!      # reply to a post
> /boost 12345              # boost a post
> /fav 12345                # favourite a post
```

### Implementation
- Use ANSI escape codes for cursor positioning and clearing
- `\033[H` — move cursor to home
- `\033[2J` — clear screen
- `\033[<row>;<col>H` — move to specific position
- Read terminal size via `TIOCGWINSZ` ioctl or `$COLUMNS`/`$LINES`
- Set terminal to raw mode for key-by-key input (`termios`)
- Poll for new posts every N seconds (configurable, default 60s)

### Terminal control
```c
// Raw mode for immediate key reading
struct termios raw;
mc_sys_ioctl(0, TCGETS, &raw);
raw.c_lflag &= ~(ICANON | ECHO);
mc_sys_ioctl(0, TCSETS, &raw);
```

### Refresh strategy
- Fetch timeline periodically (every 30-60s)
- Use `since_id` parameter to only fetch new posts
- Prepend new posts to display, scroll existing down

### CLI to launch
```bash
TOKEN=xxx masto -i gruene.social interactive
TOKEN=xxx masto -i gruene.social -I              # short flag
```

---

## File Structure

```
tools/
    masto.c             # main entry, command dispatch, env/arg parsing
    masto/              # masto implementation modules
        masto_http.c    # HTTP/1.1 over TLS
        masto_dns.c     # minimal DNS AAAA resolver (IPv6-first)
        masto_json.c    # minimal JSON parser
        masto_html.c    # HTML tag stripper
        masto_url.c     # URL/form encoding helpers
```

---

## Build Command

```bash
./bin/monacc -I core \
    tools/masto.c tools/masto/masto_http.c tools/masto/masto_dns.c \
    tools/masto/masto_json.c tools/masto/masto_html.c tools/masto/masto_url.c \
    core/mc_tls13.c core/mc_tls13_client.c core/mc_tls13_handshake.c core/mc_tls13_transcript.c core/mc_tls_record.c \
    core/mc_x25519.c core/mc_aes.c core/mc_gcm.c core/mc_sha256.c core/mc_hkdf.c core/mc_hmac.c \
    core/mc_str.c core/mc_io.c core/mc_fmt.c core/mc_snprint.c \
    -o bin/masto
```

---

## Complexity Estimates

| Phase | Description | Difficulty | LOC (est.) |
|-------|-------------|------------|------------|
| 1 | Env/CLI parsing | Easy | ~50 |
| 2 | DNS + TLS connection | Medium | ~150 |
| 3 | HTTP/1.1 client | Medium | ~200 |
| 4 | JSON parser | Medium-Hard | ~300 |
| 5 | Read timeline | Easy | ~150 |
| 6 | Post status | Easy | ~100 |
| 7 | Notifications | Easy | ~100 |
| 8 | Interactive TUI (optional) | Hard | ~400 |

**Total:** ~1400-1600 lines of C

---

## API Reference Summary

### Endpoints Used

| Method | Endpoint | Scope Required | Description |
|--------|----------|---------------|-------------|
| GET | `/api/v1/timelines/home` | `read:statuses` | Home timeline |
| GET | `/api/v1/timelines/public` | Public | Public timeline |
| POST | `/api/v1/statuses` | `write:statuses` | Post a status |
| GET | `/api/v1/notifications` | `read:notifications` | Notifications |
| GET | `/api/v1/streaming/user` | `read` | Real-time stream |

### Authentication

All authenticated requests require:
```
Authorization: Bearer <access_token>
```

### OAuth Scopes Needed

When creating an app (for future automated auth), request:
```
read:statuses write:statuses read:notifications
```

---

## Known Challenges

1. **DNS resolution** — Mastodon instances use domain names; need `dns6` or implement getaddrinfo alternative
2. **IPv6 vs IPv4** — monacc tools use IPv6; may need IPv4 fallback for some hosts
3. **JSON parsing without malloc** — fixed buffers, handle truncation gracefully
4. **HTML in content** — Status content is HTML; need to strip tags for terminal display
5. **Rate limiting** — API has rate limits (300 req/5min); handle 429 responses
6. **Unicode** — usernames/content may have emoji; pass through as UTF-8

---

## Recommended Development Order

1. **Phase 1** — Get config working, test file I/O
2. **Phase 2** — Test TLS connection (use `tls13` tool as reference)
3. **Phase 3** — Make a simple HTTPS GET request
4. **Phase 4** — Parse a hardcoded JSON string first
5. **Phase 5** — Combine: fetch timeline, parse, display
6. **Phase 6** — POST request with form encoding
7. **Phase 7** — Similar to Phase 5, just different endpoint

Start with **read-only functionality** (Phases 1-5) before adding posting.

---

## Example Session

```bash
# Set token once per shell session
$ export TOKEN="eyJhbGciOiJIUzI1N..."

# Read timeline
$ masto -i mastodon.social home -n 3
@gargron@mastodon.social · 2h ago
Eugen Rochko
Check out the new Mastodon 4.3 release!
↺ 234 · ★ 891 · ↩ 45
────────────────────────────────────
@user@other.instance · 5h ago
...

# Post a status
$ masto -i mastodon.social post "Hello from monacc! 🦣"
Posted! ID: 113547823456789

# Check notifications (can also inline the token)
$ TOKEN=xxx masto -i mastodon.social notif
★ @someone favourited your post
↺ @another boosted your post
👤 @newuser followed you
```

---

## Future Enhancements

- **Automated OAuth flow** — register app, get token without web UI
- **Media uploads** — `POST /api/v2/media`
- **Replies** — `masto reply <id> "text"`
- **Boost/Favourite** — `masto boost <id>`, `masto fav <id>`
- **Account lookup** — `masto whois @user@instance`
- **Hashtag timelines** — `masto tag linux`
