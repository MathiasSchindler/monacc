# TLS13 Requirements (for `masto` and other tools)

This document describes what we need from the existing `bin/tls13` functionality (either as a tool interface and/or as a reusable `core/` API) so that higher-level tools like `masto` can reliably implement HTTPS-based protocols (Mastodon REST, etc.) in this minimal distro.

## Current State

- `bin/tls13 hs` is a working TLS 1.3 client driver for real servers (confirmed for `gruene.social`).
- It can fetch a path via `-p PATH` (e.g. `/api/v2/instance`) and print the HTTP response.
- It is now **quiet by default** (stdout is payload-only); debug can be enabled with `-v/--debug` or `TLS13_DEBUG=1` and is written to stderr.
- It does not currently offer a way to:
  - Send custom HTTP headers (e.g. `Authorization: Bearer …`)
  - Choose method (`POST`), send a request body, set `Content-Type`
  - Build richer HTTP requests (method/headers/body)

For Mastodon:
- Public endpoints are accessible without auth (e.g. `GET /api/v2/instance`, `GET /api/v1/timelines/public`).
- Home timeline, notifications, posting require `Authorization: Bearer <TOKEN>`.

## High-Level Requirements

### 1) Act as a general-purpose TLS transport

`tls13` should be able to behave like a TLS-wrapped TCP client:
- Connect to `HOST:PORT`
- Complete TLS 1.3 handshake (SNI and timeouts)
- Then provide a way for a caller to send arbitrary application bytes and read the response bytes.

This can be exposed either:
- As a **tool mode** (recommended short-term for the minimal distro)
- As a **reusable `core/` client API** (recommended long-term)

### 2) Make HTTP usable (Mastodon needs this)

At minimum, we need to support HTTP/1.1 requests like:

```
GET /api/v1/timelines/home HTTP/1.1
Host: gruene.social
Authorization: Bearer <token>
Accept: application/json
Connection: close

```

and POST:

```
POST /api/v1/statuses HTTP/1.1
Host: gruene.social
Authorization: Bearer <token>
Content-Type: application/x-www-form-urlencoded
Content-Length: ...
Connection: close

status=Hello+world%21
```

So the TLS tool/API must support:
- Custom headers
- Custom method
- Optional request body
- Returning the raw HTTP response (including status line + headers + body)

## Proposed Tool Interface (Short-Term)

A new mode (or enhancement to `hs`) that cleanly separates handshake from I/O:

### Option A: `tls13 http`

```
# Build and send an HTTP request without writing a new HTTP client.
# The tool prints ONLY the HTTP response bytes by default.

TLS13_DEBUG=1 tls13 http [tls options] \
  -X GET|POST|... \
  -H 'Header: value'   (repeatable) \
  --data '...'         (optional) \
  --data-stdin         (read body from stdin) \
  --path /api/... \
  HOST PORT
```

Required flags/behavior:
- `-n SNI` (already supported)
- `-W TIMEOUT_MS` (already supported)
- `-D DNS_SERVER` (already supported)
- `--path PATH` or positional PATH
- `-H` repeatable header lines
- `-X` method
- `--data` / `--data-stdin`
- `--out-body` or `--quiet` so stdout is only the HTTP body (optional; helpful)
- `--out-response` so stdout is full HTTP response (status+headers+body)

Output / exit codes:
- Default stdout should be the requested output (body or full response).
- Debug/tracing should go to stderr.
- Exit code non-zero on:
  - TLS handshake failure
  - TCP connect failure
  - Timeout
  - Protocol errors

Optional:
- `--fail-http` to exit non-zero on HTTP >= 400

### Option B: `tls13 cat` (raw transport)

A simple raw transport mode:

```
# stdin -> TLS -> server
# server -> TLS -> stdout
# Like: openssl s_client, but minimal.

tls13 cat [tls options] HOST PORT
```

This mode exists now; use `-v`/`TLS13_DEBUG=1` for handshake tracing.

Then `masto` could implement HTTP by writing a request to stdin and reading stdout.

## Required Output Hygiene

To be embeddable, `tls13` needs predictable output:
- **No debug on stdout by default**.
- Prefer `stderr` for trace logs.
- Provide a `--verbose`/`--debug` switch to enable tracing.

This avoids forcing callers to implement brittle “strip debug” parsing.

## Networking Requirements

- DNS: AAAA preferred, but allow A/IPv4 fallback for instances without IPv6.
- Timeouts: handshake timeout and read timeout.
- SNI: must be configurable (already is).

## Crypto/TLS Requirements

For Mastodon `gruene.social`, current cipher support appears sufficient (`tls13 hs` succeeds).
For wider compatibility:
- TLS 1.3 cipher suites:
  - Required: `TLS_AES_128_GCM_SHA256` (0x1301) (already supported)
  - Nice-to-have: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` (only if needed)

Certificate validation:
- For early phases, **no validation** is acceptable (matches current state).
- Long-term, add at least an optional TOFU/pinning mode:
  - `--pin-spki-sha256 <hex>` or similar

## Proposed `core/` API (Long-Term)

A reusable API avoids tool-to-tool exec/pipes and enables `masto` to stream requests/responses:

- `mc_tls13_client_handshake(fd, sni, timeout_ms, &state)`
- `mc_tls13_read_app(&state, buf, cap)`
- `mc_tls13_write_app(&state, buf, len)`
- `mc_tls13_close_notify(&state)`

Where `state` includes record keys, sequence numbers, and transcript state.

This API now exists in `core/mc_tls13_client.h` (`mc_tls13_client_*`).

## Why this matters

Without these capabilities, `masto` can only access unauthenticated endpoints via `-p PATH` and cannot implement:
- `home` timeline
- `notif`
- `post`

Those all require `Authorization` headers and (for posting) request bodies.
